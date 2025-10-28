#include <iostream>
#include <iomanip>
#include <vector>
#include <memory>
#include <string>
#include <array>
#include <random>
#include <chrono>
#include <thread>
#include <fstream>
#include <algorithm>
#include <cuda_runtime.h>
#include <signal.h>
#include <cmath>

// =============================================================================
// Configuration using constexpr
// =============================================================================
namespace Config {
    constexpr size_t BATCH_SIZE = 16;
    constexpr size_t SEQ_LENGTH = 1024;
    constexpr size_t HIDDEN_DIM = 2048;
    constexpr size_t NUM_HEADS = 16;
    constexpr size_t HEAD_DIM = HIDDEN_DIM / NUM_HEADS;
    constexpr size_t FFN_DIM = HIDDEN_DIM * 4;
    constexpr size_t NUM_LAYERS = 4;
    constexpr size_t VOCAB_SIZE = 4000;
    constexpr int DURATION_SECONDS = 10;
}

// =============================================================================
// CUDA Error Checking Wrapper
// =============================================================================
class CudaError : public std::runtime_error {
public:
    explicit CudaError(const std::string& msg) : std::runtime_error(msg) {}
};

inline void checkCuda(cudaError_t result, const char* file, int line) {
    if (result != cudaSuccess) {
        throw CudaError(std::string("CUDA Error: ") +
                       cudaGetErrorString(result) +
                       " at " + file + ":" + std::to_string(line));
    }
}

#define CUDA_CHECK(call) checkCuda((call), __FILE__, __LINE__)

// =============================================================================
// RAII CUDA Memory Wrapper
// =============================================================================
template<typename T>
class CudaDeviceMemory {
private:
    T* data_ = nullptr;
    size_t size_ = 0;

public:
    explicit CudaDeviceMemory(size_t count) : size_(count) {
        if (count > 0) {
            CUDA_CHECK(cudaMalloc(&data_, count * sizeof(T)));
            std::cout << "[CUDA] Allocated " << (count * sizeof(T)) / (1024.0 * 1024.0)
                     << " MB on device" << std::endl;
        }
    }

    ~CudaDeviceMemory() {
        if (data_) {
            cudaFree(data_);
        }
    }

    // Delete copy operations
    CudaDeviceMemory(const CudaDeviceMemory&) = delete;
    CudaDeviceMemory& operator=(const CudaDeviceMemory&) = delete;

    // Allow move operations
    CudaDeviceMemory(CudaDeviceMemory&& other) noexcept
        : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    CudaDeviceMemory& operator=(CudaDeviceMemory&& other) noexcept {
        if (this != &other) {
            if (data_) cudaFree(data_);
            data_ = other.data_;
            size_ = other.size_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    T* get() { return data_; }
    const T* get() const { return data_; }
    size_t size() const { return size_; }

    void copyFromHost(const std::vector<T>& host_data) {
        if (host_data.size() != size_) {
            throw std::runtime_error("Size mismatch in copyFromHost");
        }
        CUDA_CHECK(cudaMemcpy(data_, host_data.data(),
                             size_ * sizeof(T), cudaMemcpyHostToDevice));
    }

    void copyToHost(std::vector<T>& host_data) const {
        if (host_data.size() != size_) {
            host_data.resize(size_);
        }
        CUDA_CHECK(cudaMemcpy(host_data.data(), data_,
                             size_ * sizeof(T), cudaMemcpyDeviceToHost));
    }

    void zero() {
        CUDA_CHECK(cudaMemset(data_, 0, size_ * sizeof(T)));
    }
};

// =============================================================================
// CUDA Stream Wrapper
// =============================================================================
class CudaStream {
private:
    cudaStream_t stream_ = nullptr;

public:
    CudaStream() {
        CUDA_CHECK(cudaStreamCreate(&stream_));
    }

    ~CudaStream() {
        if (stream_) {
            cudaStreamDestroy(stream_);
        }
    }

    CudaStream(const CudaStream&) = delete;
    CudaStream& operator=(const CudaStream&) = delete;

    cudaStream_t get() const { return stream_; }

    void synchronize() {
        CUDA_CHECK(cudaStreamSynchronize(stream_));
    }
};

// =============================================================================
// GPU Kernels
// =============================================================================
__global__ void attentionQKTKernel(const float* Q, const float* K, float* scores,
                                   size_t batch, size_t seq_len, size_t head_dim) {
    size_t b = blockIdx.z;
    size_t i = blockIdx.y * blockDim.y + threadIdx.y;
    size_t j = blockIdx.x * blockDim.x + threadIdx.x;

    if (b < batch && i < seq_len && j < seq_len) {
        float sum = 0.0f;
        for (size_t k = 0; k < head_dim; k++) {
            size_t q_idx = b * seq_len * head_dim + i * head_dim + k;
            size_t k_idx = b * seq_len * head_dim + j * head_dim + k;
            sum += Q[q_idx] * K[k_idx];
        }
        scores[b * seq_len * seq_len + i * seq_len + j] = sum / sqrtf(static_cast<float>(head_dim));
    }
}

__global__ void softmaxKernel(const float* input, float* output, size_t batch, size_t seq_len) {
    size_t b = blockIdx.y;
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;

    if (b < batch && i < seq_len) {
        float max_val = -INFINITY;
        for (size_t j = 0; j < seq_len; j++) {
            size_t idx = b * seq_len * seq_len + i * seq_len + j;
            max_val = fmaxf(max_val, input[idx]);
        }

        float sum = 0.0f;
        for (size_t j = 0; j < seq_len; j++) {
            size_t idx = b * seq_len * seq_len + i * seq_len + j;
            output[idx] = expf(input[idx] - max_val);
            sum += output[idx];
        }

        for (size_t j = 0; j < seq_len; j++) {
            size_t idx = b * seq_len * seq_len + i * seq_len + j;
            output[idx] /= sum;
        }
    }
}

__global__ void layerNormKernel(const float* input, float* output,
                                const float* gamma, const float* beta,
                                size_t batch, size_t seq_len, size_t hidden_dim) {
    size_t b = blockIdx.y;
    size_t i = blockIdx.x * blockDim.x + threadIdx.x;

    if (b < batch && i < seq_len) {
        float mean = 0.0f;
        for (size_t j = 0; j < hidden_dim; j++) {
            mean += input[b * seq_len * hidden_dim + i * hidden_dim + j];
        }
        mean /= hidden_dim;

        float variance = 0.0f;
        for (size_t j = 0; j < hidden_dim; j++) {
            float diff = input[b * seq_len * hidden_dim + i * hidden_dim + j] - mean;
            variance += diff * diff;
        }
        variance /= hidden_dim;

        float std = sqrtf(variance + 1e-5f);
        for (size_t j = 0; j < hidden_dim; j++) {
            size_t idx = b * seq_len * hidden_dim + i * hidden_dim + j;
            output[idx] = gamma[j] * (input[idx] - mean) / std + beta[j];
        }
    }
}

__global__ void residualAddKernel(const float* input, const float* residual,
                                  float* output, size_t n) {
    size_t idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx < n) {
        output[idx] = input[idx] + residual[idx];
    }
}

// =============================================================================
// Token Embedding using modern C++
// =============================================================================
class TokenEmbedding {
private:
    std::vector<float> embeddings_;
    size_t vocab_size_;
    size_t embedding_dim_;
    std::mt19937 rng_;
    std::uniform_real_distribution<float> dist_;

public:
    TokenEmbedding(size_t vocab_size, size_t embedding_dim)
        : vocab_size_(vocab_size)
        , embedding_dim_(embedding_dim)
        , rng_(std::random_device{}())
        , dist_(-1.0f, 1.0f) {

        embeddings_.resize(vocab_size * embedding_dim);
        std::cout << "[Init] Creating TokenEmbedding: "
                  << (embeddings_.size() * sizeof(float)) / (1024.0 * 1024.0)
                  << " MB" << std::endl;

        // Initialize with random values
        for (auto& val : embeddings_) {
            val = dist_(rng_);
        }
    }

    void embed(const std::vector<int>& tokens, std::vector<float>& output) const {
        // Output should be sized for full batch
        size_t required_size = Config::BATCH_SIZE * Config::SEQ_LENGTH * embedding_dim_;
        output.resize(required_size);
        std::fill(output.begin(), output.end(), 0.0f);

        // Fill first sequence with actual embeddings
        for (size_t i = 0; i < tokens.size() && i < Config::SEQ_LENGTH; ++i) {
            int token_id = tokens[i] % vocab_size_;
            size_t src_offset = token_id * embedding_dim_;
            size_t dst_offset = i * embedding_dim_;

            std::copy_n(embeddings_.begin() + src_offset,
                       embedding_dim_,
                       output.begin() + dst_offset);
        }
    }

    size_t getEmbeddingDim() const { return embedding_dim_; }
};

// =============================================================================
// Transformer Layer using RAII
// =============================================================================
class TransformerLayer {
private:
    CudaDeviceMemory<float> d_Q_;
    CudaDeviceMemory<float> d_K_;
    CudaDeviceMemory<float> d_V_;
    CudaDeviceMemory<float> d_attn_scores_;
    CudaDeviceMemory<float> d_attn_probs_;
    CudaDeviceMemory<float> d_attn_output_;
    CudaDeviceMemory<float> d_ln_gamma_;
    CudaDeviceMemory<float> d_ln_beta_;
    CudaDeviceMemory<float> d_residual_;

    std::vector<float> h_gamma_;
    std::vector<float> h_beta_;
    CudaStream stream_;

public:
    TransformerLayer()
        : d_Q_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HEAD_DIM)
        , d_K_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HEAD_DIM)
        , d_V_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HEAD_DIM)
        , d_attn_scores_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::SEQ_LENGTH)
        , d_attn_probs_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::SEQ_LENGTH)
        , d_attn_output_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HEAD_DIM)
        , d_ln_gamma_(Config::HIDDEN_DIM)
        , d_ln_beta_(Config::HIDDEN_DIM)
        , d_residual_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HIDDEN_DIM)
        , h_gamma_(Config::HIDDEN_DIM, 1.0f)
        , h_beta_(Config::HIDDEN_DIM, 0.0f) {

        std::cout << "[Init] Creating TransformerLayer" << std::endl;

        d_ln_gamma_.copyFromHost(h_gamma_);
        d_ln_beta_.copyFromHost(h_beta_);
    }

    void forward(const CudaDeviceMemory<float>& d_input,
                 CudaDeviceMemory<float>& d_output) {

        // Do multiple passes to increase GPU compute time
        // Pass 1: Layer norm
        dim3 ln_grid((Config::SEQ_LENGTH + 255) / 256, Config::BATCH_SIZE);
        layerNormKernel<<<ln_grid, 256, 0, stream_.get()>>>(
            d_input.get(), d_residual_.get(),
            d_ln_gamma_.get(), d_ln_beta_.get(),
            Config::BATCH_SIZE, Config::SEQ_LENGTH, Config::HIDDEN_DIM);

        // Pass 2: Multiple softmax iterations to increase GPU compute
        dim3 softmax_grid((Config::SEQ_LENGTH + 255) / 256, Config::BATCH_SIZE);
        for (int i = 0; i < 22; ++i) {  // Tuned to 22 iterations for ~50% GPU
            softmaxKernel<<<softmax_grid, 256, 0, stream_.get()>>>(
                d_attn_scores_.get(), d_attn_probs_.get(),
                Config::BATCH_SIZE, Config::SEQ_LENGTH);
        }

        // Pass 3: Residual add
        size_t total_elements = Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HIDDEN_DIM;
        for (int i = 0; i < 2; ++i) {
            residualAddKernel<<<(total_elements + 255) / 256, 256, 0, stream_.get()>>>(
                d_residual_.get(), d_input.get(), d_output.get(), total_elements);
        }

        // Pass 4: Multiple layer norm passes
        for (int i = 0; i < 2; ++i) {
            layerNormKernel<<<ln_grid, 256, 0, stream_.get()>>>(
                d_output.get(), d_residual_.get(),
                d_ln_gamma_.get(), d_ln_beta_.get(),
                Config::BATCH_SIZE, Config::SEQ_LENGTH, Config::HIDDEN_DIM);
        }

        // Pass 5: Final residual
        residualAddKernel<<<(total_elements + 255) / 256, 256, 0, stream_.get()>>>(
            d_residual_.get(), d_input.get(), d_output.get(), total_elements);

        stream_.synchronize();
    }
};

// =============================================================================
// File Cache Manager
// =============================================================================
class PromptCache {
private:
    std::string cache_dir_;
    std::vector<std::string> cached_files_;

public:
    PromptCache() {
        cache_dir_ = "/tmp/llm_cache_" + std::to_string(getpid());
        std::string cmd = "mkdir -p " + cache_dir_;
        std::system(cmd.c_str());
        std::cout << "[Init] Cache directory: " << cache_dir_ << std::endl;
    }

    ~PromptCache() {
        cleanup();
    }

    void writeCache(const std::string& key, const std::vector<float>& data, int iteration) {
        std::string filename = cache_dir_ + "/cache_" + key + "_" + std::to_string(iteration) + ".bin";
        std::ofstream file(filename, std::ios::binary);
        if (file) {
            file.write(reinterpret_cast<const char*>(data.data()),
                      data.size() * sizeof(float));
            cached_files_.push_back(filename);
        }
    }

    bool readCache(const std::string& key, std::vector<float>& data, int iteration) {
        std::string filename = cache_dir_ + "/cache_" + key + "_" + std::to_string(iteration) + ".bin";
        std::ifstream file(filename, std::ios::binary);
        if (!file) return false;

        file.seekg(0, std::ios::end);
        size_t size = file.tellg() / sizeof(float);
        file.seekg(0, std::ios::beg);

        data.resize(size);
        file.read(reinterpret_cast<char*>(data.data()), size * sizeof(float));
        return true;
    }

    void cleanup() {
        for (const auto& file : cached_files_) {
            std::remove(file.c_str());
        }
        std::string cmd = "rm -rf " + cache_dir_;
        std::system(cmd.c_str());
    }
};

// =============================================================================
// Performance Timing Statistics
// =============================================================================
struct RequestTimings {
    double cpu_compute_ms = 0.0;
    double gpu_compute_ms = 0.0;
    double io_time_ms = 0.0;

    void add(const RequestTimings& other) {
        cpu_compute_ms += other.cpu_compute_ms;
        gpu_compute_ms += other.gpu_compute_ms;
        io_time_ms += other.io_time_ms;
    }

    double total_ms() const {
        return cpu_compute_ms + gpu_compute_ms + io_time_ms;
    }
};

// =============================================================================
// Main Inference Pipeline
// =============================================================================
class InferencePipeline {
private:
    std::unique_ptr<TokenEmbedding> embedding_;
    std::vector<std::unique_ptr<TransformerLayer>> layers_;
    std::unique_ptr<PromptCache> cache_;

    CudaDeviceMemory<float> d_input_;
    CudaDeviceMemory<float> d_output_;

    std::vector<float> h_input_;
    std::vector<float> h_output_;

    // Performance tracking
    std::vector<RequestTimings> request_timings_;
    RequestTimings accumulated_timings_;
    int request_count_ = 0;

    std::array<std::string, 5> prompts_ = {
        "What is artificial intelligence?",
        "Explain transformer architectures",
        "Describe deep learning techniques",
        "What are neural networks?",
        "How does machine learning work?"
    };

public:
    InferencePipeline()
        : embedding_(std::make_unique<TokenEmbedding>(Config::VOCAB_SIZE, Config::HIDDEN_DIM))
        , cache_(std::make_unique<PromptCache>())
        , d_input_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HIDDEN_DIM)
        , d_output_(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HIDDEN_DIM) {

        std::cout << "[Init] Creating InferencePipeline with "
                  << Config::NUM_LAYERS << " layers" << std::endl;

        // Create transformer layers
        for (size_t i = 0; i < Config::NUM_LAYERS; ++i) {
            std::cout << "[Init] Creating layer " << (i + 1) << "/"
                     << Config::NUM_LAYERS << std::endl;
            layers_.push_back(std::make_unique<TransformerLayer>());
        }

        h_input_.resize(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HIDDEN_DIM);
        h_output_.resize(Config::BATCH_SIZE * Config::SEQ_LENGTH * Config::HIDDEN_DIM);

        std::cout << "[Init] Pipeline initialization complete" << std::endl;
    }

    void runRequest(int request_id) {
        RequestTimings timings;
        auto start_time = std::chrono::high_resolution_clock::now();

        // Select prompt
        const auto& prompt = prompts_[request_id % prompts_.size()];

        // ===== CPU COMPUTE: Tokenization =====
        auto cpu_start = std::chrono::high_resolution_clock::now();
        std::vector<int> tokens;
        tokens.reserve(Config::SEQ_LENGTH);
        for (size_t i = 0; i < Config::SEQ_LENGTH && i < prompt.length(); ++i) {
            tokens.push_back(static_cast<int>(prompt[i]));
        }
        while (tokens.size() < Config::SEQ_LENGTH) {
            tokens.push_back(0);  // Padding
        }

        // ===== CPU COMPUTE: Embedding lookup =====
        embedding_->embed(tokens, h_input_);

        // ===== CPU COMPUTE: Additional preprocessing (to increase CPU time) =====
        // Simulate text preprocessing, normalization, etc.
        std::vector<float> temp_buffer(Config::SEQ_LENGTH * 150);  // Increased buffer
        for (size_t i = 0; i < temp_buffer.size(); ++i) {
            temp_buffer[i] = std::sin(static_cast<float>(i)) * std::cos(static_cast<float>(request_id));
        }

        // Simulate some CPU-intensive work (sorting, searching, etc.)
        for (int iter = 0; iter < 12; ++iter) {  // Tuned to 12 iterations for ~25% CPU
            std::partial_sort(temp_buffer.begin(), temp_buffer.begin() + 1500, temp_buffer.end());
        }

        auto cpu_end = std::chrono::high_resolution_clock::now();
        timings.cpu_compute_ms = std::chrono::duration<double, std::milli>(cpu_end - cpu_start).count();

        // ===== I/O: Transfer to GPU =====
        auto io_start = std::chrono::high_resolution_clock::now();
        d_input_.copyFromHost(h_input_);
        auto io_end = std::chrono::high_resolution_clock::now();
        timings.io_time_ms += std::chrono::duration<double, std::milli>(io_end - io_start).count();

        // ===== GPU COMPUTE: Forward pass through transformer layers =====
        auto gpu_start = std::chrono::high_resolution_clock::now();
        auto* current_input = &d_input_;
        auto* current_output = &d_output_;

        for (auto& layer : layers_) {
            layer->forward(*current_input, *current_output);
            std::swap(current_input, current_output);
        }
        auto gpu_end = std::chrono::high_resolution_clock::now();
        timings.gpu_compute_ms = std::chrono::duration<double, std::milli>(gpu_end - gpu_start).count();

        // ===== I/O: Transfer back to CPU =====
        io_start = std::chrono::high_resolution_clock::now();
        current_input->copyToHost(h_output_);
        io_end = std::chrono::high_resolution_clock::now();
        timings.io_time_ms += std::chrono::duration<double, std::milli>(io_end - io_start).count();

        // ===== I/O: Cache results (file I/O) =====
        if (request_id % 2 == 0) {
            io_start = std::chrono::high_resolution_clock::now();
            cache_->writeCache("prompt_" + std::to_string(request_id % prompts_.size()),
                              h_output_, request_id);
            io_end = std::chrono::high_resolution_clock::now();
            timings.io_time_ms += std::chrono::duration<double, std::milli>(io_end - io_start).count();
        }

        // ===== I/O: Simulate network delay =====
        io_start = std::chrono::high_resolution_clock::now();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));  // Reduced from 50ms to 10ms
        io_end = std::chrono::high_resolution_clock::now();
        timings.io_time_ms += std::chrono::duration<double, std::milli>(io_end - io_start).count();

        // Track timings
        request_timings_.push_back(timings);
        accumulated_timings_.add(timings);
        request_count_++;

        // Report every 10 requests
        if (request_count_ % 10 == 0) {
            reportTimings(request_count_);
        }
    }

    void reportTimings(int last_request_id) {
        // Calculate statistics for last 10 requests
        size_t start_idx = request_timings_.size() >= 10 ? request_timings_.size() - 10 : 0;
        RequestTimings last_10;

        for (size_t i = start_idx; i < request_timings_.size(); ++i) {
            last_10.add(request_timings_[i]);
        }

        int count = request_timings_.size() - start_idx;
        double avg_cpu = last_10.cpu_compute_ms / count;
        double avg_gpu = last_10.gpu_compute_ms / count;
        double avg_io = last_10.io_time_ms / count;
        double avg_total = (avg_cpu + avg_gpu + avg_io);

        std::cout << "\n[Performance Report] Requests " << (last_request_id - count + 1)
                  << " - " << last_request_id << " (last " << count << " requests):" << std::endl;
        std::cout << "  CPU Compute:  " << std::fixed << std::setprecision(2)
                  << avg_cpu << " ms (" << (avg_cpu / avg_total * 100) << "%)" << std::endl;
        std::cout << "  GPU Compute:  " << avg_gpu << " ms ("
                  << (avg_gpu / avg_total * 100) << "%)" << std::endl;
        std::cout << "  I/O (+ Net):  " << avg_io << " ms ("
                  << (avg_io / avg_total * 100) << "%)" << std::endl;
        std::cout << "  Total Time:   " << avg_total << " ms/request" << std::endl;
    }

    void printFinalReport() {
        if (request_count_ == 0) return;

        std::cout << "\n=============================================================" << std::endl;
        std::cout << "Final Performance Report (" << request_count_ << " total requests)" << std::endl;
        std::cout << "=============================================================" << std::endl;

        double avg_cpu = accumulated_timings_.cpu_compute_ms / request_count_;
        double avg_gpu = accumulated_timings_.gpu_compute_ms / request_count_;
        double avg_io = accumulated_timings_.io_time_ms / request_count_;
        double avg_total = (avg_cpu + avg_gpu + avg_io);

        std::cout << "Average per request:" << std::endl;
        std::cout << "  CPU Compute:  " << std::fixed << std::setprecision(2)
                  << avg_cpu << " ms (" << (avg_cpu / avg_total * 100) << "%)" << std::endl;
        std::cout << "  GPU Compute:  " << avg_gpu << " ms ("
                  << (avg_gpu / avg_total * 100) << "%)" << std::endl;
        std::cout << "  I/O (+ Net):  " << avg_io << " ms ("
                  << (avg_io / avg_total * 100) << "%)" << std::endl;
        std::cout << "  Total Time:   " << avg_total << " ms/request" << std::endl;
        std::cout << "\nTotal time breakdown:" << std::endl;
        std::cout << "  CPU Compute:  " << accumulated_timings_.cpu_compute_ms << " ms" << std::endl;
        std::cout << "  GPU Compute:  " << accumulated_timings_.gpu_compute_ms << " ms" << std::endl;
        std::cout << "  I/O (+ Net):  " << accumulated_timings_.io_time_ms << " ms" << std::endl;
        std::cout << "=============================================================" << std::endl;
    }
};

// =============================================================================
// Global cleanup handler
// =============================================================================
std::unique_ptr<InferencePipeline> g_pipeline;
volatile sig_atomic_t g_interrupted = 0;

void signalHandler(int signum) {
    std::cout << "\n[Signal] Received signal " << signum << ", cleaning up..." << std::endl;
    g_interrupted = 1;
    g_pipeline.reset();
    std::cout << "[Cleanup] Complete. Exiting." << std::endl;
    exit(signum);
}

// =============================================================================
// Main
// =============================================================================
int main() {
    try {
        std::cout << "=============================================================" << std::endl;
        std::cout << "Modern C++ LLM Inference Simulator" << std::endl;
        std::cout << "=============================================================" << std::endl;
        std::cout << "Configuration:" << std::endl;
        std::cout << "  - Batch Size: " << Config::BATCH_SIZE << std::endl;
        std::cout << "  - Sequence Length: " << Config::SEQ_LENGTH << std::endl;
        std::cout << "  - Hidden Dimension: " << Config::HIDDEN_DIM << std::endl;
        std::cout << "  - Number of Layers: " << Config::NUM_LAYERS << std::endl;
        std::cout << "  - Duration: " << Config::DURATION_SECONDS << " seconds" << std::endl;
        std::cout << "=============================================================" << std::endl;

        // Initialize CUDA
        CUDA_CHECK(cudaSetDevice(0));
        std::cout << "[Init] CUDA device initialized" << std::endl;

        // Setup signal handlers
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);

        // Create pipeline
        g_pipeline = std::make_unique<InferencePipeline>();

        // Run request processing loop
        auto start = std::chrono::steady_clock::now();
        int request_id = 0;

        std::cout << "\n[Starting] Processing requests for " << Config::DURATION_SECONDS
                  << " seconds..." << std::endl;

        while (!g_interrupted) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();

            if (elapsed >= Config::DURATION_SECONDS) {
                break;
            }

            g_pipeline->runRequest(request_id);
            request_id++;
        }

        std::cout << "\n=============================================================" << std::endl;
        std::cout << "Completed " << request_id << " requests in "
                  << Config::DURATION_SECONDS << " seconds" << std::endl;
        std::cout << "Average throughput: "
                  << (request_id / static_cast<double>(Config::DURATION_SECONDS))
                  << " requests/second" << std::endl;
        std::cout << "=============================================================" << std::endl;

        // Print final performance report
        g_pipeline->printFinalReport();

        g_pipeline.reset();

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return 1;
    }
}
