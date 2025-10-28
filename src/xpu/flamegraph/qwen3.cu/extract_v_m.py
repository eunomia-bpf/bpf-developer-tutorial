#modified from a utility in llama.cpp
#!/usr/bin/env python3
import string
import logging
import sys
from pathlib import Path

logger = logging.getLogger("reader")

# Necessary to load the local gguf package
# sys.path.insert(0, str(Path(__file__).parent.parent))

from gguf.gguf_reader import GGUFReader

# 된다
def extract_merges_to_txt(reader, output_file="merges.txt"):
    parts = reader.fields["tokenizer.ggml.merges"].parts

    # Skip initial header/metadata parts
    start_idx = 6

    # Crop to full merge pairs only
    if (len(parts) - start_idx) % 2 != 0:
        print(f"Merges field has odd number of parts after header. Truncating last.")
        parts = parts[:len(parts) - 1]

    with open(output_file, "w", encoding="utf-8") as f:
        for i in range(start_idx, len(parts), 2):
            merge_bytes = parts[i]
            try:
                merge_str = bytes(merge_bytes).decode("utf-8")
            except Exception:
                merge_str = bytes(merge_bytes).decode("utf-8", errors="replace")
            f.write(merge_str + "\n")

    print(f"Extracted {((len(parts) - start_idx) //2)} merges to {output_file}")


def extract_vocab_to_txt(reader, output_file="vocab.txt"):
    tokens = reader.fields["tokenizer.ggml.tokens"].parts
    with open(output_file, "w", encoding="utf-8") as f:
        # Start at 6 (where real tokens start)
        for i in range(6, len(tokens), 2):
            token_bytes = tokens[i]
            # Only process tokens that are arrays of uint8
            if getattr(token_bytes, 'dtype', None) == 'uint8':
                b = bytes(token_bytes)
                b = b.rstrip(b'\x00')
                if b:  # skip empty
                    try:
                        token_str = b.decode("utf-8")
                    except Exception:
                        token_str = b.decode("utf-8", errors="replace")
                    f.write(token_str + "\n")
    print(f"Extraction complete ({(len(tokens) -6) //2} tokens written).")


def read_gguf_file(gguf_file_path):
    """
    Reads and prints key-value pairs and tensor information from a GGUF file in an improved format.

    Parameters:
    - gguf_file_path: Path to the GGUF file.
    """

    reader = GGUFReader(gguf_file_path)
    
    extract_merges_to_txt(reader)
    extract_vocab_to_txt(reader)

    # List all key-value pairs in a columnized format
    print("Key-Value Pairs:") # noqa: NP100
    max_key_length = max(len(key) for key in reader.fields.keys())
    
    for key, field in reader.fields.items():
        value = field.parts[field.data[0]]
        print(f"{key:{max_key_length}} : {value}")

        try:
            value1 = ''.join(chr(x) for x in value)  # Convert [103, 112, 116, 50] to "gpt2"
            print(f"{key:{max_key_length}} : {value1}")  # Print key and value
        except:
            pass    
        #elif isinstance(value, bytes):
        #value2 = value.tobytes().decode('utf-8')  # If value is bytes, decode to string
        #print(f"{key:{max_key_length}} : {value2}")  # Print key and value


    for key, field in reader.fields.items():
        value = field.parts[field.data[0]]

        # Try to convert to string if it looks like string data
        if isinstance(value, list) and all(isinstance(x, int) for x in value):
            # Try UTF-8 first, fallback to ASCII, else show the list
            try:
                value_str = bytes(value).decode('utf-8')
            except (UnicodeDecodeError, ValueError, TypeError):
                try:
                    if all(32 <= x <= 126 for x in value):  # printable ASCII
                        value_str = ''.join(chr(x) for x in value)
                    else:
                        value_str = str(value)
                except Exception:
                    value_str = str(value)
            value = value_str

        elif isinstance(value, bytes):
            try:
                value = value.decode('utf-8')
            except UnicodeDecodeError:
                value = str(value)

        elif hasattr(value, 'tobytes'):  # numpy ndarray/memmap/etc
            try:
                value = value.tobytes().decode('utf-8')
            except UnicodeDecodeError:
                value = repr(value)
                # OR, for arrays: np.array2string(value) for small arrays
            except Exception:
                value = repr(value)
        else:
            value = str(value)

        print(f"{key:{max_key_length}} : {value}")

    # List all tensors
    print("Tensors:") # noqa: NP100
    tensor_info_format = "{:<30} | Shape: {:<15} | Size: {:<12} | Quantization: {}"
    print(tensor_info_format.format("Tensor Name", "Shape", "Size", "Quantization")) # noqa: NP100
    print("-" * 80) # noqa: NP100
    for tensor in reader.tensors:
        shape_str = "x".join(map(str, tensor.shape))
        size_str = str(tensor.n_elements)
        quantization_str = tensor.tensor_type.name
        print(tensor_info_format.format(tensor.name, shape_str, size_str, quantization_str)) # noqa: NP100


if __name__ == '__main__':
    if len(sys.argv) < 2:
        logger.info("Usage: reader.py <path_to_gguf_file>")
        sys.exit(1)
    gguf_file_path = sys.argv[1]
    read_gguf_file(gguf_file_path)
