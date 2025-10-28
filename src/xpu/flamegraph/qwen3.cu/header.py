import struct
import sys
import logging

logger = logging.getLogger(__name__)

def read_string(f):
    """Read a string from the file"""
    length = struct.unpack('<Q', f.read(8))[0]
    try:
        return f.read(length).decode('utf-8')
    except UnicodeDecodeError:
        # If UTF-8 fails, try latin-1 or return as hex
        f.seek(-length, 1)  # Go back
        data = f.read(length)
        return f"<binary data: {data[:50].hex()}{'...' if len(data) > 50 else ''}>"

def read_gguf_file(file_path):
    """Read GGUF file and extract header information"""
    with open(file_path, 'rb') as f:
        # Read magic number
        magic = f.read(4)
        if magic != b'GGUF':
            raise ValueError("Not a valid GGUF file")
        
        # Read version
        version = struct.unpack('<I', f.read(4))[0]
        
        # Read tensor count and metadata count
        tensor_count = struct.unpack('<Q', f.read(8))[0]
        metadata_count = struct.unpack('<Q', f.read(8))[0]
        
        output = []
        output.append(f"MAGIC={magic.decode('ascii')}")
        output.append(f"VERSION={version}")
        output.append(f"TENSOR_COUNT={tensor_count}")
        output.append(f"METADATA_COUNT={metadata_count}")
        
        # Read metadata
        try:
            for i in range(metadata_count):
                key = read_string(f)
                value_type = struct.unpack('<I', f.read(4))[0]
                
                # Read value based on type
                if value_type == 0:  # UINT8
                    value = struct.unpack('<B', f.read(1))[0]
                elif value_type == 1:  # INT8
                    value = struct.unpack('<b', f.read(1))[0]
                elif value_type == 2:  # UINT16
                    value = struct.unpack('<H', f.read(2))[0]
                elif value_type == 3:  # INT16
                    value = struct.unpack('<h', f.read(2))[0]
                elif value_type == 4:  # UINT32
                    value = struct.unpack('<I', f.read(4))[0]
                elif value_type == 5:  # INT32
                    value = struct.unpack('<i', f.read(4))[0]
                elif value_type == 6:  # FLOAT32
                    value = struct.unpack('<f', f.read(4))[0]
                elif value_type == 7:  # BOOL
                    value = struct.unpack('<B', f.read(1))[0] != 0
                elif value_type == 8:  # STRING
                    value = read_string(f)
                elif value_type == 9:  # ARRAY
                    array_type = struct.unpack('<I', f.read(4))[0]
                    array_length = struct.unpack('<Q', f.read(8))[0]
                    value = f"ARRAY_TYPE={array_type},ARRAY_LENGTH={array_length}"
                    # Skip array data safely
                    try:
                        for _ in range(array_length):
                            if array_type == 8:  # STRING array
                                read_string(f)
                            elif array_type == 4:  # UINT32 array
                                f.read(4)
                            elif array_type == 5:  # INT32 array
                                f.read(4)
                            elif array_type == 6:  # FLOAT32 array
                                f.read(4)
                            elif array_type == 0:  # UINT8 array
                                f.read(1)
                            elif array_type == 1:  # INT8 array
                                f.read(1)
                            else:
                                # Skip unknown array type
                                f.read(4)  # Assume 4 bytes per element
                    except Exception as e:
                        value = f"ARRAY_TYPE={array_type},ARRAY_LENGTH={array_length},ERROR=parse_error"
                elif value_type == 10:  # UINT64
                    value = struct.unpack('<Q', f.read(8))[0]
                elif value_type == 11:  # INT64
                    value = struct.unpack('<q', f.read(8))[0]
                elif value_type == 12:  # FLOAT64
                    value = struct.unpack('<d', f.read(8))[0]
                else:
                    value = f"UNKNOWN_TYPE={value_type}"
                
                # Clean key name for C compatibility
                clean_key = key.replace('.', '_').replace('-', '_').upper()
                output.append(f"{clean_key}={value}")
        except Exception as e:
            output.append(f"METADATA_ERROR={e}")
            return
        
        # Read tensor info (without data)
        for i in range(tensor_count):
            name = read_string(f)
            n_dimensions = struct.unpack('<I', f.read(4))[0]
            dimensions = []
            for _ in range(n_dimensions):
                dimensions.append(struct.unpack('<Q', f.read(8))[0])
            tensor_type = struct.unpack('<I', f.read(4))[0]
            offset = struct.unpack('<Q', f.read(8))[0]
            
            # Clean tensor name for C compatibility
            clean_name = name.replace('.', '_').replace('-', '_').upper()
            output.append(f"TENSOR_{i}_NAME={clean_name}")
            output.append(f"TENSOR_{i}_DIMENSIONS={','.join(map(str, dimensions))}")
            output.append(f"TENSOR_{i}_TYPE={tensor_type}")
            output.append(f"TENSOR_{i}_OFFSET={offset}")
        
        # Write to file
        with open('header.txt', 'w', encoding='utf-8') as out_file:
            out_file.write('\n'.join(output))
        
        print("Header information saved to header.txt")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        logger.info("Usage: reader.py <path_to_gguf_file>")
        sys.exit(1)
    
    gguf_file_path = sys.argv[1]
    read_gguf_file(gguf_file_path)
