/* Inference for GGUF Qwen-3 models in pure C */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/mman.h>

#include <cuda_runtime.h>


#ifdef USE_CUBLAS
#include <cublas_v2.h>

// cublas handle
cublasHandle_t g_cublas_handle = nullptr;

void create_cublas_handle()
{
    cublasStatus_t stat = cublasCreate(&g_cublas_handle); // FIXME cublasDestroy
    if (stat != CUBLAS_STATUS_SUCCESS)
    {
        printf("CUBLAS initialization failed\n");
        exit(EXIT_FAILURE);
    }
}
void destroy_cublas_handle()
{
    cublasStatus_t stat = cublasDestroy(g_cublas_handle);
    if (stat != CUBLAS_STATUS_SUCCESS)
    {
        printf("CUBLAS initialization failed\n");
        exit(EXIT_FAILURE);
    }
}
#endif

// ----------------------------------------------------------------------------
// Transformer model
typedef struct {
    int dim; // transformer dimension
    int hidden_dim; // for ffn layers
    int n_layers; // number of layers
    int n_heads; // number of query heads
    int n_kv_heads; // number of key/value heads (can be < query heads because of multiquery)
    int vocab_size; // vocabulary size
    int seq_len; // max sequence length
    int head_dim; // attention dimension
} Config;

typedef struct {
    // token embedding table
    float* token_embedding_table;    // (vocab_size, dim)
    // weights for rmsnorms in each layer
    float* rms_att_weight; // (layer, dim)
    float* rms_ffn_weight; // (layer, dim)
    // weights for matmuls
    float* wq; // (layer, dim, n_heads * head_dim)
    float* wk; // (layer, dim, n_kv_heads * head_dim)
    float* wv; // (layer, dim, n_kv_heads * head_dim)
    float* wo; // (layer, n_heads * head_dim, dim)
    float* wq_norm; // (layer, head_dim)
    float* wk_norm; // (layer, head_dim)
    // weights for ffn. w1 = up, w3 = gate, w2 = down
    float* w1; // (layer, dim, hidden_dim)
    float* w2; // (layer, hidden_dim, dim)
    float* w3; // (layer, dim, hidden_dim)
    // final rmsnorm
    float* rms_final_weight; // (dim,)
    // Same as token_embedding_table. GGUF has the final layer anyway
    float* wcls;
} TransformerWeights;

typedef struct {
    // current wave of activations
    float* x; // activation at current time stamp (dim,)
    float* xb; // buffer (dim,)
    float* xb2; // an additional buffer just for convenience (dim,)
    float* xb3; // an additional buffer just for convenience (att_head_dim,)
    float* hb; // buffer for hidden dimension in the ffn (hidden_dim,)
    float* hb2; // buffer for hidden dimension in the ffn (hidden_dim,)
    float* q;   // query (att_head_dim,)
    float* k; // key (dim,)
    float* v; // value (dim,)
    float* att; // buffer for scores/attention values (n_heads, seq_len)
    float* logits; // output logits
    
    float *d_logits; // CUDA logits
    
    // kv cache
    float* key_cache;   // (layer, seq_len, dim)
    float* value_cache; // (layer, seq_len, dim)
} RunState;

typedef struct {
    Config config; // the hyperparameters of the architecture (the blueprint)
    TransformerWeights weights; // the weights of the model
    RunState state; // buffers for the "wave" of activations in the forward pass
    int fd; // file descriptor for memory mapping
    float* data; // memory mapped data pointer
    ssize_t file_size; // size of the checkpoint file in bytes
} Transformer;


// Macro for checking CUDA errors
#define CUDA_CHECK(call) do { \
    cudaError_t err = call; \
    if (err != cudaSuccess) { \
        fprintf(stderr, "CUDA error at %s:%d - %s\n", __FILE__, __LINE__, cudaGetErrorString(err)); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

void malloc_run_state(RunState* s, Config *p) {
    // we calloc instead of malloc to keep valgrind happy
    int att_head_dim = p->n_heads * p->head_dim; 
    int kv_dim = p->n_kv_heads * p->head_dim;  // 1024  

    CUDA_CHECK(cudaMalloc(&s->x, p->dim * sizeof(float))); 
    CUDA_CHECK(cudaMalloc(&s->xb, p->dim * sizeof(float)));  
    CUDA_CHECK(cudaMalloc(&s->xb2, p->dim * sizeof(float)));  
    CUDA_CHECK(cudaMalloc(&s->xb3, att_head_dim * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->hb, p->hidden_dim * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->hb2, p->hidden_dim * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->q,  att_head_dim * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->k,  kv_dim * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->v,  kv_dim * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->att,  p->n_heads * p->seq_len * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->d_logits,  p->vocab_size * sizeof(float)));
    CUDA_CHECK(cudaMalloc(&s->key_cache,  p->n_layers * p->seq_len * kv_dim * sizeof(float)));  
    CUDA_CHECK(cudaMalloc(&s->value_cache,  p->n_layers * p->seq_len * kv_dim * sizeof(float)));

    s->logits = (float *)calloc(p->vocab_size, sizeof(float));

    // ensure all mallocs went fine
    if (!s->x || !s->xb || !s->xb2 || !s->xb3 || !s->hb || !s->hb2 || !s->q || !s->k || !s->v || !s->att || !s->logits || !s->d_logits || !s->key_cache || !s->value_cache) {
        fprintf(stderr, "malloc failed!\n");
        exit(EXIT_FAILURE);
    }
}

void free_run_state(RunState* s) {
    CUDA_CHECK(cudaFree(s->x));
    CUDA_CHECK(cudaFree(s->xb));
    CUDA_CHECK(cudaFree(s->xb2));
    CUDA_CHECK(cudaFree(s->xb3));
    CUDA_CHECK(cudaFree(s->hb));
    CUDA_CHECK(cudaFree(s->hb2));
    CUDA_CHECK(cudaFree(s->q));
    CUDA_CHECK(cudaFree(s->k));
    CUDA_CHECK(cudaFree(s->v));
    CUDA_CHECK(cudaFree(s->att));
    CUDA_CHECK(cudaFree(s->d_logits));
    CUDA_CHECK(cudaFree(s->key_cache));
    CUDA_CHECK(cudaFree(s->value_cache));
    free(s->logits);
}

// Map GGUF layers to transformer weights
void memory_map_weights(TransformerWeights* w, Config* p, void* pt) {
    //unsigned long long n_layers = p->n_layers;
    float *ptr = (float*) pt; 

    w->wcls = ptr;   // last layer in TR
    ptr += p->vocab_size * p->dim;
    w->rms_final_weight = ptr; // right before the last
    ptr += p->dim;
    w->token_embedding_table = ptr; // first layer  
    ptr += p->vocab_size * p->dim;
    w->wk = ptr;
    ptr += p->dim * (p->n_kv_heads * p->head_dim);  // 1024 x 1024 = dim (1024) x  num_kv_heads (8) x p->head_dim (128)
    w->wk_norm = ptr;
    ptr += p->head_dim; //head_dim (128)
    w->rms_att_weight = ptr;
    ptr += p->dim; //dimension (1024)
    w->wo = ptr;
    ptr += (p->n_heads * p->head_dim) * p->dim;  // attention heads (16) x head dim (128) * dim
    w->wq = ptr;
    ptr += p->dim * (p->n_heads * p->head_dim);
    w->wq_norm = ptr;
    ptr += p->head_dim; //head_dim (128)     
    w->wv = ptr;
    ptr += p->dim * (p->n_kv_heads * p->head_dim); // equal to wk
    w->w2 = ptr;
    ptr += p->hidden_dim * p->dim; //ffn.down 3072 *1024 
    w->w3 = ptr;
    ptr += p->dim * p->hidden_dim; // ffn.gate
    w->rms_ffn_weight = ptr;
    ptr += p->dim;                 // ffn.norm
    w->w1 = ptr;
    ptr += p->dim * p->hidden_dim; //ffn.up
}

// --------------------------------------
// read GGUF
void read_checkpoint(char *checkpoint, Config *config, TransformerWeights* weights, int* fd, float** data, ssize_t* file_size) {
    FILE *file = fopen(checkpoint, "rb");
    if (!file) { fprintf(stderr, "Couldn't open file %s\n", checkpoint); exit(EXIT_FAILURE); }
    fseek(file, 0, SEEK_END); // move file pointer to end of file
    *file_size = (ssize_t)ftell(file); // get the file size, in bytes
    fclose(file);
    
    //printf("file size is %zd", *file_size);

    // memory map the Transformer weights into the data pointer
    *fd = open(checkpoint, O_RDONLY); // open in read only mode
    if (*fd == -1) { fprintf(stderr, "open failed!\n"); exit(EXIT_FAILURE); }
    
    *data = (float*) mmap(NULL, *file_size, PROT_READ, MAP_PRIVATE, *fd, 0);
    if (*data == MAP_FAILED) { fprintf(stderr, "mmap failed!\n"); exit(EXIT_FAILURE); }

    // CUDA
    float* d_weights_ptr;
    // gguf total header = file size - (last tensor size + last offset)
    size_t weights_size = *file_size - 5951648; // skip header bytes. header_size = 5951648 TODO    
    CUDA_CHECK(cudaMalloc((void**)&d_weights_ptr, weights_size));
    CUDA_CHECK(cudaMemcpy(d_weights_ptr, (*data) + 5951648/4, weights_size, cudaMemcpyHostToDevice));

    memory_map_weights(weights, config, d_weights_ptr);
}

void build_transformer(Transformer *t, char *checkpoint_path) {
    // read in the Weights from the GGUF
    read_checkpoint(checkpoint_path, &t->config, &t->weights, &t->fd, &t->data, &t->file_size);
    // allocate the RunState buffers
    malloc_run_state(&t->state, &t->config);
}

void free_transformer(Transformer *t) {
    if (t->data && t->data != MAP_FAILED) {
        munmap(t->data, t->file_size);
        t->data = NULL;
    }
    // CUDA_CHECK(cudaFree(t->weights.token_embedding_table));
}

// load the GGUF config file
void load_config(Transformer *t) {
    FILE *f = fopen("header.txt", "r");
    if (!f) {perror("Failed to open header.txt"); exit(1);}

    char line[512];
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        char *cfg = strtok(line, " ");
        while (cfg) {
            char *eq = strchr(cfg, '=');
            if (!eq) {
                //fprintf(stderr, "Warning: malformed cfg on line %d: %s\n", line_num, cfg);
                cfg = strtok(NULL, " ");
                continue;
            }

            *eq = '\0';
            char *key = cfg;
            char *val = eq + 1;

            // Match keys
            if (strcmp(key, "QWEN3_EMBEDDING_LENGTH") == 0) {
                t->config.dim = atoi(val);
            } else if (strcmp(key, "QWEN3_FEED_FORWARD_LENGTH") == 0) {
                t->config.hidden_dim = atoi(val);
            } else if (strcmp(key, "QWEN3_BLOCK_COUNT") == 0) {
                t->config.n_layers = atoi(val);
            } else if (strcmp(key, "QWEN3_ATTENTION_HEAD_COUNT") == 0) {
                t->config.n_heads = atoi(val);
            } else if (strcmp(key, "QWEN3_ATTENTION_HEAD_COUNT_KV") == 0) {
                t->config.n_kv_heads = atoi(val);
            } else if (strcmp(key, "QWEN3_CONTEXT_LENGTH") == 0) {
                t->config.seq_len = atoi(val);
                t->config.seq_len = 4096; //OVERWRITE TEMP
            } else if (strcmp(key, "QWEN3_ATTENTION_KEY_LENGTH") == 0) {
                t->config.head_dim = atoi(val);
            }else if (strncmp(key, "TOKENIZER_GGML_TOKENS", 22) == 0) { 
                char *len_ptr = strstr(val, "ARRAY_LENGTH=");  //handling nested config
                if (len_ptr) {
                    t->config.vocab_size = atoi(len_ptr + strlen("ARRAY_LENGTH="));
                }
            }
            cfg = strtok(NULL, " ");
        }
    }
    fclose(f);
}

// ----------------------------------------------------------------------------
// neural net blocks; the dynamics of the Transformer
// CUDA version

// Utility routine to divide a into ceiling of b parts
int divUp(int a, int b)
{
    return (a - 1) / b + 1;
}

const int num_threads_lrg = 1024;
const int num_threads_med = 256;

//========== RMS =====
__global__ void rmsnorm_kernel(float *o, float *x, float *weight, int size, int elementsPerThread)
{
    __shared__ float sdata[num_threads_lrg];
    
    // compute partial sum of squares
    float ss = 0.0f;
    for (int i = 0; i < elementsPerThread; i++)
    {
        int j = threadIdx.x + i * num_threads_lrg;
        if (j < size)
            ss += x[j] * x[j];
    }
    
    sdata[threadIdx.x] = ss;
    __syncthreads();
    
    for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (threadIdx.x < stride)
            sdata[threadIdx.x] += sdata[threadIdx.x + stride];
        __syncthreads();
    }
    
    if (threadIdx.x == 0) {
        ss = sdata[0] / size + 1e-6f;
        sdata[0] = 1.0f / sqrtf(ss);
    }
    __syncthreads();
    ss = sdata[0];
    
    for (int i = 0; i < elementsPerThread; i++)
    {
        int j = threadIdx.x + i * num_threads_lrg;
        if (j < size)
            o[j] = weight[j] * (ss * x[j]);
    }
}

void rmsnorm(float *o, float *x, float *weight, int size)
{
    int elementsPerThread = divUp(size, num_threads_lrg);
    rmsnorm_kernel<<<1, num_threads_lrg>>>(o, x, weight, size, elementsPerThread);
}


__global__ void rmsnorm_kernel_multihead(float *o, float *x, float *weight, 
                                         int head_dim, int elementsPerThread, 
                                         int n_heads)
{
    __shared__ float sdata[num_threads_lrg];
    
    // Get head index from block ID
    int head = blockIdx.x;
    if (head >= n_heads) return;
    
    // Calculate offsets for this head
    float *head_input = x + head * head_dim;
    float *head_output = o + head * head_dim;
    // Note: weight is shared across all heads (same normalization weights)
    
    // compute partial sum of squares
    float ss = 0.0f;
    for (int i = 0; i < elementsPerThread; i++)
    {
        int j = threadIdx.x + i * num_threads_lrg;
        if (j < head_dim)
            ss += head_input[j] * head_input[j];
    }
    
    sdata[threadIdx.x] = ss;
    __syncthreads();
    
    for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (threadIdx.x < stride)
            sdata[threadIdx.x] += sdata[threadIdx.x + stride];
        __syncthreads();
    }
    
    if (threadIdx.x == 0) {
        ss = sdata[0] / head_dim + 1e-6f;
        sdata[0] = 1.0f / sqrtf(ss);
    }
    __syncthreads();
    ss = sdata[0];
    
    for (int i = 0; i < elementsPerThread; i++)
    {
        int j = threadIdx.x + i * num_threads_lrg;
        if (j < head_dim)
            head_output[j] = weight[j] * (ss * head_input[j]);
    }
}


void rmsnorm_multihead(float *o, float *x, float *weight, int head_dim, int n_heads)
{
    int elementsPerThread = divUp(head_dim, num_threads_lrg);
    
    // Launch one block per head
    rmsnorm_kernel_multihead<<<n_heads, num_threads_lrg>>>(
        o, x, weight, head_dim, elementsPerThread, n_heads
    );
}


//========== Softmax in GPU =====
__device__ void softmax_gpu(float *__restrict__ x, int size)
{
    __shared__ float sdata[num_threads_lrg];
    int tid = threadIdx.x;
    int step = blockDim.x;
    
    // find max value (for numerical stability)
    float max_val = tid < size ? x[tid] : -INFINITY;
    for (int i = tid + step; i < size; i += step)
    {
        if (x[i] > max_val)
            max_val = x[i];
    }
    
    sdata[tid] = max_val;
    __syncthreads();
    
    for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (tid < stride)
            sdata[tid] = fmaxf(sdata[tid], sdata[tid + stride]);
        __syncthreads();
    }
    max_val = sdata[0];
    
    // exp and sum
    float sum = 0.0f;
    for (int i = tid; i < size; i += step)
    {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }

    sdata[tid] = sum;
    __syncthreads();
    
    for (int stride = blockDim.x / 2; stride > 0; stride >>= 1) {
        if (tid < stride)
            sdata[tid] += sdata[tid + stride];
        __syncthreads();
    }
    sum = sdata[0];
    
    // normalize
    for (int i = tid; i < size; i += step)
        x[i] /= sum;
}

void softmax(float* x, int size) {
    // find max value (for numerical stability)
    float max_val = x[0];
    for (int i = 1; i < size; i++) {
        if (x[i] > max_val) {
            max_val = x[i];
        }
    }
    // exp and sum
    float sum = 0.0f;
    for (int i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    // normalize
    for (int i = 0; i < size; i++) {
        x[i] /= sum;
    }
}


// Use cuBLAS for matmul to leverage this included, high-performance library.
#ifdef USE_CUBLAS
void matmul(float *xout, float *x, float *w, int n, int d)
{
    // W (d,n) @ x (n,) -> xout (d,)
    // W is stored in this order: (n=0,d=0), (n=1,d=0), (n=2,d=0), ...
    // so W is n x d in cublas terms & we'll need to transpose.
    // Sgemv does y = alpha * op(A) * x + beta * y (modifying y)
    //   where op can transpose the matrix A
    // Translating to our local vars, that is
    // xout = 1.0*op(w)*x + 0.0*xout
    float alpha = 1.0f;
    float beta = 0.0f; // when this is 0, xout will not be used for input
    cublasSgemv(g_cublas_handle, CUBLAS_OP_T, n, d, &alpha, w, n, x, 1, &beta, xout, 1);
}
#else

__global__ void matmul_kernel(float *xout, float *x, float *w, int n, int d) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    int tid = threadIdx.x;
    
    extern __shared__ float shared_x[];
    
    // Load x into shared memory in chunks
    for (int offset = 0; offset < n; offset += blockDim.x) {
        if (offset + tid < n) {
            shared_x[tid] = x[offset + tid];
        }
        __syncthreads();
        
        if (i < d) {
            float sum = 0.0f;
            int chunk_size = min(blockDim.x, n - offset);
            
            // Vectorized loads and computation
            float4 *w_vec = (float4*)(w + i * n + offset);
            float4 *x_vec = (float4*)shared_x;
            
            int vec_ops = chunk_size / 4;
            for (int v = 0; v < vec_ops; v++) {
                float4 w4 = w_vec[v];
                float4 x4 = x_vec[v];
                sum += w4.x * x4.x + w4.y * x4.y + w4.z * x4.z + w4.w * x4.w;
            }
            
            // Handle remaining elements
            for (int j = vec_ops * 4; j < chunk_size; j++) {
                sum += w[i * n + offset + j] * shared_x[j];
            }
            
            if (offset == 0) xout[i] = sum;
            else xout[i] += sum;
        }
        __syncthreads();
    }
}

void matmul(float *xout, float *x, float *w, int n, int d) {
    int block_size = 256;
    int grid_size = (d + block_size - 1) / block_size;
    int shared_mem = block_size * sizeof(float);
    matmul_kernel<<<grid_size, block_size, shared_mem>>>(xout, x, w, n, d);
}
#endif

// multihead attention
__global__ void multi_head_attention_kernel(int pos, int seq_len, float *sq, float *satt, float *sxb, float *key_cache, float *value_cache, int kv_dim, int kv_mul, int head_size, int loff)
{
    int h = blockIdx.x;
    // get the query vector for this head
    float *q = sq + h * head_size;
    // attention scores for this head
    float *att = satt + h * seq_len;
    // iterate over all timesteps, including the current one
    // In CUDA, each thread does a small portion of the calc
    for (int t = threadIdx.x; t <= pos; t += blockDim.x)
    {
        // get the key vector for this head and at this timestep
        float *k = key_cache + loff + t * kv_dim + (h / kv_mul) * head_size;
        // calculate the attention score as the dot product of q and k
        float score = 0.0f;
        for (int i = 0; i < head_size; i++)
        {
            score += q[i] * k[i];
        }
        score /= sqrtf(head_size);
        // save the score to the attention buffer
        att[t] = score;
    }
    // above was this threads portion of the iteration.  wait for all threads to finish
    __syncthreads();

    // softmax the scores to get attention weights, from 0..pos inclusively
    softmax_gpu(att, pos + 1);
    __syncthreads();

    // weighted sum of the values, store back into xb
    // NOTE: by swapping the order of the for loops (vs. C) a simpler
    // version of the code accomplishes the same task and fits more
    // naturally with the CUDA way of subdividing the problem.
    float *xb = sxb + h * head_size;
    for (int i = threadIdx.x; i < head_size; i += blockDim.x)
    {
        float val = 0.0f;
        for (int t = 0; t <= pos; t++)
        {
            // get the value vector for this head and at this timestep
            float *v = value_cache + loff + t * kv_dim + (h / kv_mul) * head_size;
            // get the attention weight for this timestep
            float a = att[t];
            val += a * v[i];
        }
        xb[i] = val;
    }
}
void multi_head_attention(int pos, Config *p, RunState *s, int kv_dim, int kv_mul, int head_size, int loff)
{
    multi_head_attention_kernel<<<p->n_heads, num_threads_lrg>>>(pos, p->seq_len, s->q, s->att, s->xb3, s->key_cache, s->value_cache, kv_dim, kv_mul, head_size, loff);
}  // Fixed xb to xb3

//-------Activation-----------
__global__ void f_silu_elementwise_mul_w3_kernel(float *shb, float *shb2, int hidden_dim)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < hidden_dim)
    {
        float val = shb2[i];
        // silu(x)=x*σ(x), where σ(x) is the logistic sigmoid
        val *= (1.0f / (1.0f + expf(-val)));
        // elementwise multiply with w3(x)
        val *= shb[i];
        shb2[i] = val;
    }
}
void f_silu_elementwise_mul_w3(RunState *s, int hidden_dim)
{
    f_silu_elementwise_mul_w3_kernel<<<divUp(hidden_dim, num_threads_med), num_threads_med>>>(s->hb, s->hb2, hidden_dim);
}

//------Residual Connection----------
__global__ void accum_kernel(float *a, float *b, int size)
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < size)
    {
        a[i] += b[i];
    }
}

void accum(float *a, float *b, int size)
{
    accum_kernel<<<divUp(size, num_threads_med), num_threads_med>>>(a, b, size);
}


// Unified kernel for both Q and K RoPE rotation
__global__ void RoPe_rotation_kernel_multihead(int pos, float *tensor, int head_dim, 
                                               int kv_dim, int att_head_dim, int n_heads)
{
    // Get head and element indices
    int head = blockIdx.x;
    int i = threadIdx.x;
    
    if (head >= n_heads || i >= head_dim / 2) return;
    
    // Calculate offset for this head
    float *head_tensor = tensor + head * head_dim;
    
    float freq = 1.0f / powf(1000000.0f, (float)i / (head_dim / 2));
    float fcr = cosf(pos * freq);
    float fci = sinf(pos * freq);

    // Rotate tensor head (works for both Q and K)
    float x = head_tensor[i];
    float y = head_tensor[i + head_dim / 2];
    head_tensor[i] = x * fcr - y * fci;
    head_tensor[i + head_dim / 2] = x * fci + y * fcr;
}

// Unified host function for both Q and K RoPE rotation
void RoPe_rotation_multihead(int pos, float *tensor, int head_dim, int kv_dim, 
                            int att_head_dim, int n_heads)
{
    // Launch one block per head, threads per element
    RoPe_rotation_kernel_multihead<<<n_heads, head_dim / 2>>>(
        pos, tensor, head_dim, kv_dim, att_head_dim, n_heads
    );
}


//======================================
// FORWARD PASS
float *forward(Transformer *transformer, int token, int pos)
{
    Config* p = &transformer->config;
    TransformerWeights* w = &transformer->weights;
    RunState* s = &transformer->state;
    
    int kv_dim = p->n_kv_heads * p->head_dim;  
    int kv_mul = p->n_heads / p->n_kv_heads; 
    int att_head_dim = p->n_heads * p->head_dim; 

    int layer_offset = 62923776/4; // offset to the GGUF next layer for the same tensor type TODO
    
    // copy the token embedding into s->x in GPU, STARTING POINT - x is passing through.
    float *content_row = w->token_embedding_table + token * p->dim;
    CUDA_CHECK(cudaMemcpy(s->x, content_row, p->dim * sizeof(*s->x), cudaMemcpyHostToDevice));

    // forward all the layers
    for (int l = 0; l < p->n_layers; l++) {
        // kv cache
        int loff = l * p->seq_len * kv_dim; 
        s->k = s->key_cache + loff + pos * kv_dim;
        s->v = s->value_cache + loff + pos * kv_dim;

        // attention rmsnorm
        rmsnorm(s->xb, s->x, w->rms_att_weight + l * layer_offset, p->dim);

        // Query, key, value computation
        matmul(s->q, s->xb, w->wq + l *layer_offset, p->dim, att_head_dim); 
        matmul(s->k, s->xb, w->wk + l *layer_offset, p->dim, kv_dim);  
        matmul(s->v, s->xb, w->wv + l *layer_offset, p->dim, kv_dim);

        // Apply RMSNorm to ALL query heads
        rmsnorm_multihead(s->q, s->q, w->wq_norm + l * layer_offset, p->head_dim, p->n_heads);
        // Apply RoPE to Q
        RoPe_rotation_multihead(pos, s->q, p->head_dim, kv_dim, att_head_dim, p->n_heads);

        // Apply RMSNorm to ALL key heads 
        rmsnorm_multihead(s->k, s->k, w->wk_norm + l * layer_offset, p->head_dim, p->n_kv_heads);
        // Apply RoPE to K
        RoPe_rotation_multihead(pos, s->k, p->head_dim, kv_dim, att_head_dim, p->n_kv_heads);
              
        multi_head_attention(pos, p, s, kv_dim, kv_mul, p->head_dim, loff);
        
        // Output projection
        matmul(s->xb2, s->xb3, w->wo + l *layer_offset, att_head_dim, p->dim);

        // Grouped-query attetion ends. Residual connection
        accum(s->x, s->xb2, p->dim);


        // FFN
        rmsnorm(s->xb, s->x, w->rms_ffn_weight + l *layer_offset /* * p->dim*/ , p->dim);
        matmul(s->hb, s->xb, w->w1 + l *layer_offset, p->dim, p->hidden_dim); // Up
        matmul(s->hb2, s->xb, w->w3 + l *layer_offset, p->dim, p->hidden_dim); // Gate
        f_silu_elementwise_mul_w3(s, p->hidden_dim);                          // Activation
        matmul(s->xb, s->hb2, w->w2 + l *layer_offset, p->hidden_dim, p->dim); // Down

        // residual connection
        accum(s->x, s->xb, p->dim);        
    }

    // Final norm after layers and right before logiting
    rmsnorm(s->x, s->x, w->rms_final_weight, p->dim);

    // Calc logits in GPU and move it to CPU
    matmul(s->d_logits, s->x, w->wcls, p->dim, p->vocab_size);
    CUDA_CHECK(cudaMemcpy(s->logits, s->d_logits, p->vocab_size * sizeof(float), cudaMemcpyDeviceToHost));

    return s->logits;
}

// ----------------------------------------------------------------------------
// TOKENIZER
// The Byte Pair Encoding (BPE) Tokenizer that translates strings <-> tokens

typedef struct {
    char **vocab;
    float *merge_scores;
    int vocab_size;
    unsigned int max_token_length;
    unsigned int bos_token_id;
    unsigned int eos_token_id;
    char prompt_template[1024];
    char system_prompt_template[1024];
} Tokenizer;

// ========== GLOBALS ==========

// TODO
#define MAX_VOCAB 151936
#define MAX_MERGES 151386 
#define MAX_TOKENS 1024
#define MAX_TOKEN_LEN 32

char *vocab[MAX_VOCAB];
int num_vocab = 0;

typedef struct {
    char left[MAX_TOKEN_LEN];
    char right[MAX_TOKEN_LEN];
    char merged[MAX_TOKEN_LEN * 2];
    int rank;
} MergeRule;

MergeRule merges[MAX_MERGES];
int merge_count = 0;

unsigned int byte_to_unicode[256];
char unicode_bytes[256][5]; 

//special token
const char *special_tokens[] = {
    "<|im_start|>",
    "<|im_end|>",
    "<think>",
    "</think>"
};
int num_special_tokens = sizeof(special_tokens) / sizeof(special_tokens[0]);

typedef struct {
    int *data;         // token ID array
    size_t size;       // number of tokens stored
    size_t capacity;   // total allocated capacity
} TokenBuffer;

// ========== LOAD VOCAB ==========
void load_vocab(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        exit(1);
    }

    char line[512];  // large enough to hold most tokens safely
    int line_num = 0;

    while (fgets(line, sizeof(line), f)) {
        line_num++;

        // Remove trailing newline / carriage return
        line[strcspn(line, "\r\n")] = '\0';

        // Skip empty lines
        if (line[0] == '\0') continue;

        if (num_vocab >= MAX_VOCAB) {
            fprintf(stderr, "Error: vocab exceeds MAX_VOCAB (%d)\n", MAX_VOCAB);
            break;
        }

        vocab[num_vocab] = strdup(line);
        if (!vocab[num_vocab]) {
            fprintf(stderr, "Error: strdup failed on line %d\n", line_num);
            exit(1);
        }
        num_vocab++;
    }
    fclose(f);
}

void free_vocab() {
    for (int i = 0; i < num_vocab; i++) {
        free(vocab[i]);  // Free each string
        vocab[i] = NULL; 
    }
    num_vocab = 0;
}

// ========== LOAD MERGES ==========
void load_merges(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror("merges.txt"); exit(1); }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || isspace(line[0])) continue;
        char *a = strtok(line, " \t\r\n");
        char *b = strtok(NULL, " \t\r\n");
        if (!a || !b) continue;
        strncpy(merges[merge_count].left, a, MAX_TOKEN_LEN);
        strncpy(merges[merge_count].right, b, MAX_TOKEN_LEN);
        snprintf(merges[merge_count].merged, sizeof(merges[merge_count].merged), "%s%s", a, b);
        merges[merge_count].rank = merge_count;
        merge_count++;
    }
    fclose(f);
}

bool pair_equals(const char *a, const char *b, const char *left, const char *right) {
    return strcmp(a, left) == 0 && strcmp(b, right) == 0;
}

int get_merge_rank(const char *left, const char *right) {
    for (int i = 0; i < merge_count; i++) {
        if (pair_equals(left, right, merges[i].left, merges[i].right)) {
            return merges[i].rank;
        }
    }
    return INT_MAX;
}

// ========== BYTE-TO-UNICODE ==========
void init_byte_unicode_map() {
    int n = 0;    
    for (int b = 0; b < 256; b++) {
        // party for gpt-2 based tokenizer
        if ((b >= 33 && b <= 126) ||    // ASCII
            (b >= 161 && b <= 172) ||   // Latin-1 
            (b >= 174 && b <= 255)) {   // Latin-1 except 173
            byte_to_unicode[b] = b;
        } else {
            byte_to_unicode[b] = 256 + n++;  // Map out of Unicode range
        }
        
        // Direct UTF-8 encoding
        uint32_t cp = byte_to_unicode[b];
        if (cp < 128) {                  // 1-byte UTF-8
            unicode_bytes[b][0] = cp;
            unicode_bytes[b][1] = '\0';
        } 
        else if (cp < 2048) {            // 2-byte UTF-8
            unicode_bytes[b][0] = 0xC0 | (cp >> 6);
            unicode_bytes[b][1] = 0x80 | (cp & 0x3F);
            unicode_bytes[b][2] = '\0';
        } 
        else {                           // 3-byte UTF-8
            unicode_bytes[b][0] = 0xE0 | (cp >> 12);
            unicode_bytes[b][1] = 0x80 | ((cp >> 6) & 0x3F);
            unicode_bytes[b][2] = 0x80 | (cp & 0x3F);
            unicode_bytes[b][3] = '\0';
        }
    }
}

// TODO. Returns -1 if not a special token, else index into vocab[]
int match_special_token(const char *str, int *match_len) {  
    for (int i = 0; i < num_special_tokens; i++) {
        const char *tok = special_tokens[i];
        int len = strlen(tok);
        if (strncmp(str, tok, len) == 0) {
            // Now check if this token exists in vocab
            for (int j = 0; j < 151936; j++) { 
                if (strcmp(vocab[j], tok) == 0) {
                    *match_len = len;
                    return j; // return token ID
                }
            }
        }
    }   
    return -1;
}

void build_tokenizer(Tokenizer* t) {
    load_vocab("vocab.txt");
    load_merges("merges.txt");
    init_byte_unicode_map();
}    
 
// build buffer 
void build_token_buffer(TokenBuffer *tb, size_t initial_capacity) {
    tb->data = (int *) malloc(initial_capacity * sizeof(int));
    if (!tb->data) { perror("malloc"); exit(1); }
    tb->size = 0;
    tb->capacity = initial_capacity;
}

void free_token_buffer(TokenBuffer *tb) {
    free(tb->data);
    tb->data = NULL;
    tb->size = 0;
    tb->capacity = 0;
}
void append_tokens(TokenBuffer *tb, const int *tokens, size_t n) {
    if (tb->size + n > tb->capacity) {
        while (tb->size + n > tb->capacity) tb->capacity *= 2;
        tb->data = (int *) realloc(tb->data, tb->capacity * sizeof(int));
        if (!tb->data) { perror("realloc"); exit(1); }
    }
    memcpy(&tb->data[tb->size], tokens, n * sizeof(int));
    tb->size += n;
}

void encode(Tokenizer* t, char* rendered_prompt, int* prompt_tokens, int* num_prompt_tokens, int multi_turn) {
    if (rendered_prompt == NULL) { fprintf(stderr, "cannot encode NULL text\n"); exit(EXIT_FAILURE); }
    char *tokens[MAX_TOKENS];
    int count = 0;

    const char *p = rendered_prompt;

    while (*p) {
        int match_len = 0;
        int special_id = match_special_token(p, &match_len);
        if (special_id >= 0) {
            // Special token found → store its string
            tokens[count++] = strdup(vocab[special_id]);  // Store as string, not ID
            p += match_len;
            continue;
        }

        // Not a special token → convert byte to unicode
        unsigned char b = *p++;
        tokens[count++] = strdup(unicode_bytes[b]);
    }

    // === BPE merge ===
    bool changed = true;
    while (changed) {
        int best_rank = INT_MAX;
        int best_pos = -1;

        for (int i = 0; i < count - 1; i++) {
            int rank = get_merge_rank(tokens[i], tokens[i + 1]);
            if (rank < best_rank) {
                best_rank = rank;
                best_pos = i;
            }
        }

        if (best_pos == -1) break;

        // if either token is a special token, skip merge 
        if (tokens[best_pos][0] == '<' && strchr(tokens[best_pos], '|') &&  
            tokens[best_pos + 1][0] == '<' && strchr(tokens[best_pos + 1], '|')) {
            break; // don't merge special tokens
        }

        // Merge
        char *merged = (char *) malloc(MAX_TOKEN_LEN * 2);
        snprintf(merged, MAX_TOKEN_LEN * 2, "%s%s", tokens[best_pos], tokens[best_pos + 1]);
        free(tokens[best_pos]);
        free(tokens[best_pos + 1]);
        tokens[best_pos] = merged;
        for (int i = best_pos + 1; i < count - 1; i++) {
            tokens[i] = tokens[i + 1];
        }
        count--;
        changed = true;
    }

    // === Map tokens to token IDs ===
    int token_ids[MAX_TOKENS];
    int token_id_count = 0;

    for (int i = 0; i < count; i++) {
        int id = -1;
        for (int j = 0; j < 151936; j++) {
            if (strcmp(tokens[i], vocab[j]) == 0) {
                id = j;
                break;
            }
        }

        if (id == -1) {
            fprintf(stderr, "Token not found in vocab: [%s]\n", tokens[i]);
        } else {
            token_ids[token_id_count++] = id;
            //printf("[%s] → id = %d\n", tokens[i], id);
        }
    // TODO
    for (int i = 0; i < token_id_count; i++) {
        prompt_tokens[i] = token_ids[i];
    }
        *num_prompt_tokens = token_id_count;
    }
}
 
// ========== Decoding logic==========
// Inverse byte-to-unicode: utf8 string → byte value (0–255)
int unicode_to_byte(const char *utf8) {
    for (int b = 0; b < 256; b++) {
        if (strcmp(utf8, unicode_bytes[b]) == 0)
            return b;
    }
    return -1; // not found
}

char *decode_token_id(int token_id) {
    const char *encoded = vocab[token_id];
    char *out = (char *) malloc(1024);
    int rlen = 0;
    for (int i = 0; encoded[i]; ) {
        int matched = 0;
        for (int len = 1; len <= 3 && encoded[i + len - 1]; len++) {
            char utf8[5] = {0};
            strncpy(utf8, &encoded[i], len);
            int b = unicode_to_byte(utf8);
            if (b >= 0) {
                out[rlen++] = (char)b;
                i += len;
                matched = 1;
                break;
            }
        }
        if (!matched) break;
    }
    out[rlen] = '\0';
    return out;
}

// ----------------------------------------------------------------------------
// The Sampler, which takes logits and returns a sampled token
// sampling can be done in a few ways: greedy argmax, sampling, top-p sampling

typedef struct {
    float prob;
    int index;
} ProbIndex; // struct used when sorting probabilities during top-p sampling

typedef struct {
    int vocab_size;
    ProbIndex *probindex; // buffer used in top-p sampling
    float temperature;
    float topp;
    unsigned long long rng_state;
} Sampler;

int sample_argmax(float *probabilities, int n) {
    // return the index that has the highest probability
    int max_i = 0;
    float max_p = probabilities[0];
    for (int i = 1; i < n; i++) {
        if (probabilities[i] > max_p) {
            max_i = i;
            max_p = probabilities[i];
        }
    }
    return max_i;
}

int sample_mult(float *probabilities, int n, float coin) {
    // sample index from probabilities (they must sum to 1!)
    // coin is a random number in [0, 1), usually from random_f32()
    float cdf = 0;
    for (int i = 0; i < n; i++) {
        cdf += probabilities[i];
        if (coin < cdf)
            return i;
    }
    return n - 1; // in case of rounding errors
}

int compare(const void *a, const void *b) {
    ProbIndex *a_ = (ProbIndex *) a;
    ProbIndex *b_ = (ProbIndex *) b;
    if (a_->prob > b_->prob) return -1;
    if (a_->prob < b_->prob) return 1;
    return 0;
}

int sample_topp(float *probabilities, int n, float topp, ProbIndex *probindex, float coin) {
    // top-p sampling (or "nucleus sampling") samples from the smallest set of
    // tokens that exceed probability topp. This way we never sample tokens that
    // have very low probabilities and are less likely to go "off the rails".
    // coin is a random number in [0, 1), usually from random_f32()

    int n0 = 0;
    // quicksort indices in descending order of probabilities
    // values smaller than (1 - topp) / (n - 1) cannot be part of the result
    // so for efficiency we crop these out as candidates before sorting
    const float cutoff = (1.0f - topp) / (n - 1);
    for (int i = 0; i < n; i++) {
        if (probabilities[i] >= cutoff) {
            probindex[n0].index = i;
            probindex[n0].prob = probabilities[i];
            n0++;
        }
    }
    qsort(probindex, n0, sizeof(ProbIndex), compare);

    // truncate the list where cumulative probability exceeds topp
    float cumulative_prob = 0;
    int last_idx = n0 - 1; // in case of rounding errors consider all elements
    for (int i = 0; i < n0; i++) {
        cumulative_prob += probindex[i].prob;
        if (cumulative_prob > topp) {
            last_idx = i;
            break; // we've exceeded topp by including last_idx
        }
    }

    // sample from the truncated list
    float r = coin * cumulative_prob;
    float cdf = 0;
    for (int i = 0; i <= last_idx; i++) {
        cdf += probindex[i].prob;
        if (r < cdf)
            return probindex[i].index;
    }
    return probindex[last_idx].index; // in case of rounding errors
}

void build_sampler(Sampler* sampler, int vocab_size, float temperature, float topp, unsigned long long rng_seed) {
    sampler->vocab_size = vocab_size;
    sampler->temperature = temperature;
    sampler->topp = topp;
    sampler->rng_state = rng_seed;
    // buffer only used with nucleus sampling; may not need but it's ~small
    sampler->probindex = (ProbIndex *) malloc(sampler->vocab_size * sizeof(ProbIndex));
}

void free_sampler(Sampler* sampler) {
    free(sampler->probindex);
}

unsigned int random_u32(unsigned long long *state) {
    // xorshift rng: https://en.wikipedia.org/wiki/Xorshift#xorshift.2A
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    return (*state * 0x2545F4914F6CDD1Dull) >> 32;
}
float random_f32(unsigned long long *state) { // random float32 in [0,1)
    return (random_u32(state) >> 8) / 16777216.0f;
}

int sample(Sampler* sampler, float* logits) {
    // sample the token given the logits and some hyperparameters
    int next;
    if (sampler->temperature == 0.0f) {
        // greedy argmax sampling: take the token with the highest probability
        next = sample_argmax(logits, sampler->vocab_size);
    } else {
        // apply the temperature to the logits
        for (int q=0; q<sampler->vocab_size; q++) { logits[q] /= sampler->temperature; }
        // apply softmax to the logits to get the probabilities for next token
        softmax(logits, sampler->vocab_size);
        // flip a (float) coin (this is our source of entropy for sampling)
        float coin = random_f32(&sampler->rng_state);
        // we sample from this distribution to get the next token
        if (sampler->topp <= 0 || sampler->topp >= 1) {
            // simply sample from the predicted probability distribution
            next = sample_mult(logits, sampler->vocab_size, coin);
        } else {
            // top-p (nucleus) sampling, clamping the least likely tokens to zero
            next = sample_topp(logits, sampler->vocab_size, sampler->topp, sampler->probindex, coin);
        }
    }
    return next;
}

// ----------------------------------------------------------------------------
// utilities: time
long time_in_ms() {
    // return time in milliseconds, for benchmarking the model speed
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return time.tv_sec * 1000 + time.tv_nsec / 1000000;
}

// ------------------------------------------------------------------------
// read input
void read_stdin(const char* guide, char* buffer, size_t bufsize) {
    // read a line from stdin, up to but not including \n
    printf("%s", guide);
    if (fgets(buffer, bufsize, stdin) != NULL) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0'; 
        }
    }
}

// ----------------------------------------------------------------------------
// chat loop
void chat(Transformer* transformer, Tokenizer* tokenizer, Sampler* sampler, char* cli_user_prompt, char* cli_system_prompt, int think_on, int multi_turn, int tps, TokenBuffer* tb, int single_prompt) {
    // buffers for reading the system prompt and user prompt from stdin
    char system_prompt[512];
    char user_prompt[8192];
    char rendered_prompt[8192];
    int num_prompt_tokens = 0;
    int* prompt_tokens = (int* )malloc(8192 * sizeof(int));
    //int user_idx;

    // start the main loop
    int8_t user_turn = 1; // user starts
    int next;        // will store the next token in the sequence
    int token;       // stores the current token to feed into the transformer
    //int prev_token;
    int pos = 0;     // position in the sequence
    double timer = -1.0;   // TPS timer start
    int count = 0;         // decoded token

     while (1) {
        if (user_turn) {
                if (pos == 0){
                    if (!single_prompt) {
                        read_stdin("Enter system prompt (or Enter to skip): ", system_prompt, sizeof(system_prompt));
                    } else {
                        system_prompt[0] = '\0';
                    }
                }
                if (!single_prompt) {
                    read_stdin("Q: ", user_prompt, sizeof(user_prompt));
                } else {
                    if (cli_user_prompt) {
                        strncpy(user_prompt, cli_user_prompt, sizeof(user_prompt) - 1);
                        user_prompt[sizeof(user_prompt) - 1] = '\0';
                    } else {
                        user_prompt[0] = '\0';
                    }
                }
                // terminate if user enters a blank prompt
                if (!user_prompt[0]) {
                    break;
                }

            // render user/system prompts for Qwen3 
            if (pos == 0 && system_prompt[0] != '\0') {
                char system_template[] = "<|im_start|>system\n%s<|im_end|>\n<|im_start|>user\n%s<|im_end|>\n<|im_start|>assistant\n";
                sprintf(rendered_prompt, system_template, system_prompt, user_prompt);
            } else {
                char user_template[] = "<|im_start|>user\n%s<|im_end|>\n<|im_start|>assistant\n";
                sprintf(rendered_prompt, user_template, user_prompt);
            }

            if (!think_on) {
                strcat(rendered_prompt, "<think>\n\n</think>\n");
            }

            // encode the rendered prompt into tokens
            encode(tokenizer, rendered_prompt, prompt_tokens, &num_prompt_tokens, multi_turn);
            pos = 0; // reset the user index
            user_turn = 0;  
            if (multi_turn) {
            append_tokens(tb, prompt_tokens, num_prompt_tokens);
                for (size_t i = 0; i < tb->size; i++) {
                    // printf("%d ", tb->data[i]);
                }
                printf("\n");
            }
            printf("A: ");
        }

        if (pos < (multi_turn ? tb->size : num_prompt_tokens)) {
            token = (multi_turn) ? tb->data[pos] : prompt_tokens[pos];
        } else {
            token = next;
        }
        //printf("right before foreward: %d\n", token);
        // forward the transformer to get logits for the next token
        float* logits = forward(transformer, token, pos);
        next = sample(sampler, logits);

        pos++;
        //printf("num_prompt_tokens: %d \n", num_prompt_tokens);
        // decoding and printing
        if (pos >= (multi_turn ? tb->size : num_prompt_tokens)) {
            if (multi_turn) {
                append_tokens(tb, &next, 1);
                //printf("next token: %d\n",  next);
            }
            
            if (next == 151645) { // EOS token ID - TODO
                printf("\n");
                user_turn = 1;

                // TPS
                if (tps) {
                fprintf(stderr, "tok/s: %f\n", count / (double)(time_in_ms() - timer) * 1000);
                timer = -1;
                count = 0;
                }

                // Exit after single prompt
                if (single_prompt) {
                    break;
                }
            }
            else {
            char *decoded = decode_token_id(next);
            printf("%s", decoded);
            fflush(stdout);
            free(decoded);

                if (tps) {
                    count += 1;
                    // timer starts after the first token generation
                    if (timer == -1.0) {timer = time_in_ms();}
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
// CLI
void error_usage() {
    fprintf(stderr, "Usage:   run <FP32 GGUF file> [options]\n");
    fprintf(stderr, "Example: ./run Qwen3-0.6B-FP32.gguf\n");
    fprintf(stderr, "         ./run Qwen3-0.6B-FP32.gguf -q \"What is CUDA?\"\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -t <float>  temperature in [0,inf], default 0.6\n");
    fprintf(stderr, "  -p <float>  p value in top-p (nucleus) sampling in [0,1] default 0.95\n");
    fprintf(stderr, "  -s <int>    random seed, default time(NULL)\n");
    fprintf(stderr, "  -m <int>    multi-turn: 0 = off (defualt), 1 = on\n");
    fprintf(stderr, "  -k <int>    reasoning: 0 = off (defualt), 1 = on\n");
    fprintf(stderr, "  -r <int>    TPS: 0 = off (defualt), 1 = on\n");
    fprintf(stderr, "  -q <string> single prompt mode (run once and exit)\n");
    exit(EXIT_FAILURE);
}


int main(int argc, char *argv[]) {
    // default parameters
    char *checkpoint_path = NULL;  // e.g. out/model.bin
    float temperature = 0.6f;   // 0.0 = greedy deterministic. 1.0 = original. don't set higher
    float topp = 0.95f;          // top-p in nucleus sampling. 1.0 = off. 0.9 works well, but slower
    int steps = 256;            // number of steps to run for
    char *prompt = NULL;        // prompt string
    unsigned long long rng_seed = 0; // seed rng with time by default
    char *system_prompt = NULL; // the (optional) system prompt to use in chat mode
    int multi_turn = 0;  // multi-turn conversation
    int think_on = 0;    //  reasoning on
    int tps = 0;         // TPS
    int single_prompt = 0; // single prompt mode

    if (argc >= 2) { checkpoint_path = argv[1]; } else { error_usage(); }
    for (int i = 2; i < argc; i+=2) {
        // do some basic validation
        if (i + 1 >= argc) { error_usage(); } // must have arg after flag
        if (argv[i][0] != '-') { error_usage(); } // must start with dash
        if (strlen(argv[i]) != 2) { error_usage(); } // must be -x (one dash, one letter)
        // read in the args
        if (argv[i][1] == 't') { temperature = atof(argv[i + 1]); }
        else if (argv[i][1] == 'p') { topp = atof(argv[i + 1]); }
        else if (argv[i][1] == 's') { rng_seed = atoi(argv[i + 1]); }
        else if (argv[i][1] == 'q') { prompt = argv[i + 1]; single_prompt = 1; }
        else if (argv[i][1] == 'm') {if ((argv[i+1][0] == '0' || argv[i+1][0] == '1') && argv[i+1][1] == '\0') {
        multi_turn = argv[i+1][0] - '0';} else { error_usage(); } }
        else if (argv[i][1] == 'k') {if ((argv[i+1][0] == '0' || argv[i+1][0] == '1') && argv[i+1][1] == '\0') {
        think_on = argv[i+1][0] - '0';} else { error_usage(); } }
        else if (argv[i][1] == 'r') {if ((argv[i+1][0] == '0' || argv[i+1][0] == '1') && argv[i+1][1] == '\0') {
        tps = argv[i+1][0] - '0';} else { error_usage(); } }
        else { error_usage(); }
    }

    // parameter validation/overrides
    if (rng_seed <= 0) rng_seed = (unsigned int)time(NULL);
    if (temperature < 0.0) temperature = 0.0;
    if (topp < 0.0 || 1.0 < topp) topp = 0.9;
    if (steps < 0) steps = 0;

    // read config
    Transformer transformer;
    load_config(&transformer);

    // build the Transformer via the GGUF file
    build_transformer(&transformer, checkpoint_path);  

    // build the Tokenizer 
    Tokenizer tokenizer;
    build_tokenizer(&tokenizer); 

    // multi-turn buffer
    TokenBuffer tb;
    build_token_buffer(&tb, 1024);

    Sampler sampler;
    build_sampler(&sampler, transformer.config.vocab_size, temperature, topp, rng_seed);

    #ifdef USE_CUBLAS
    // cuBlas handle
    create_cublas_handle();
    #endif

    if (!single_prompt) {
        printf("Multi-turn = %s, thinKing = %s, tps(R) = %s, Temperature = %.2f, top-P = %.2f\n", multi_turn ? "on" : "off", think_on ? "on" : "off", tps ? "on" : "off", temperature, topp);
        printf("Press Enter to exit the chat\n");
    }

    // run!
    chat(&transformer, &tokenizer, &sampler, prompt, system_prompt, think_on, multi_turn, tps, &tb, single_prompt); 

    // memory and file handles cleanup
    free_sampler(&sampler); 
    free_vocab();
    free_token_buffer(&tb);
    free_transformer(&transformer);

    #ifdef USE_CUBLAS
    destroy_cublas_handle();
    #endif

    return 0;
}
