import time
import tracemalloc
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# Performance metrics
def read_input(input_data):
    """
    Read the input data from a file or string.
    """
    try:
        with open(input_data, "rb") as f:
            data = f.read()
        print(f"Input read as a file. Size: {len(data)} bytes")
        return data
    except FileNotFoundError:
        data = input_data.encode()
        print(f"Input read as a string. Size: {len(data)} bytes")
        return data


def measure_memory_rsa_operation(operation, *args, **kwargs):
    """
    Measure memory usage for an RSA operation.
    """
    tracemalloc.start()
    result = operation(*args, **kwargs)
    _, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, peak_memory


def benchmark_rsa(input_data, iterations, key_sizes):
    """
    Benchmark RSA encryption and decryption for multiple key sizes.
    """
    message = read_input(input_data)
    results = {}

    for key_size in key_sizes:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()

        max_block_size = key_size // 8 - 42
        if len(message) > max_block_size:
            print(f"Input exceeds maximum block size for RSA ({max_block_size} bytes). Truncating input.")
            message = message[:max_block_size]

        encryption_times = []
        encryption_memory = []
        decryption_times = []
        decryption_memory = []

        for _ in range(iterations):
            # Encryption
            start_time = time.time()
            encrypted_message, enc_memory = measure_memory_rsa_operation(
                public_key.encrypt,
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            end_time = time.time()
            encryption_times.append(end_time - start_time)
            encryption_memory.append(enc_memory)

            # Decryption
            start_time = time.time()
            _, dec_memory = measure_memory_rsa_operation(
                private_key.decrypt,
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            end_time = time.time()
            decryption_times.append(end_time - start_time)
            decryption_memory.append(dec_memory)

        # Calculate averages and throughput
        avg_encryption_time = sum(encryption_times) / iterations
        avg_decryption_time = sum(decryption_times) / iterations
        encryption_throughput = iterations / sum(encryption_times)
        decryption_throughput = iterations / sum(decryption_times)
        avg_encryption_memory = sum(encryption_memory) / iterations
        avg_decryption_memory = sum(decryption_memory) / iterations

        results[key_size] = {
            "Key Size (bits)": key_size,
            "Iterations": iterations,
            "Input Size (bytes)": len(message),
            "Average Encryption Time (s)": avg_encryption_time,
            "Average Decryption Time (s)": avg_decryption_time,
            "Encryption Throughput (ops/sec)": encryption_throughput,
            "Decryption Throughput (ops/sec)": decryption_throughput,
            "Average Encryption Memory (bytes)": avg_encryption_memory,
            "Average Decryption Memory (bytes)": avg_decryption_memory,
        }

    return results


def display_statistics(results):
    """
    Display the RSA benchmark statistics in the terminal.
    """
    print("\n--- RSA Benchmark Statistics and Analysis ---")
    for key_size, metrics in results.items():
        print(f"\nKey Size: {key_size} bits")
        for metric, value in metrics.items():
            print(f"{metric}: {value}")


def plot_results(results):
    """
    Plot graphs for RSA benchmark results in a single window.
    """
    key_sizes = list(results.keys())

    input_sizes = [results[key]["Input Size (bytes)"] for key in key_sizes]
    encryption_times = [results[key]["Average Encryption Time (s)"] for key in key_sizes]
    decryption_times = [results[key]["Average Decryption Time (s)"] for key in key_sizes]
    encryption_memory = [results[key]["Average Encryption Memory (bytes)"] for key in key_sizes]
    decryption_memory = [results[key]["Average Decryption Memory (bytes)"] for key in key_sizes]
    encryption_throughput = [results[key]["Encryption Throughput (ops/sec)"] for key in key_sizes]
    decryption_throughput = [results[key]["Decryption Throughput (ops/sec)"] for key in key_sizes]

    # Plot Encryption and Decryption Times
    plt.figure(figsize=(10, 6))
    plt.plot(key_sizes, encryption_times, marker='o', label="Encryption Time (s)")
    plt.plot(key_sizes, decryption_times, marker='o', label="Decryption Time (s)")
    plt.title("Encryption and Decryption Times vs Key Size")
    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Time (s)")
    plt.legend()
    plt.grid()
    plt.show()

    # Plot Memory Usage
    plt.figure(figsize=(10, 6))
    plt.plot(key_sizes, encryption_memory, marker='o', label="Encryption Memory (bytes)")
    plt.plot(key_sizes, decryption_memory, marker='o', label="Decryption Memory (bytes)")
    plt.title("Memory Usage vs Key Size")
    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Memory Usage (bytes)")
    plt.legend()
    plt.grid()
    plt.show()

    # Plot Throughput
    plt.figure(figsize=(10, 6))
    plt.plot(key_sizes, encryption_throughput, marker='o', label="Encryption Throughput (ops/sec)")
    plt.plot(key_sizes, decryption_throughput, marker='o', label="Decryption Throughput (ops/sec)")
    plt.title("Throughput vs Key Size")
    plt.xlabel("RSA Key Size (bits)")
    plt.ylabel("Throughput (ops/sec)")
    plt.legend()
    plt.grid()
    plt.show()


if __name__ == "__main__":
    input_data = input("Enter a file path or a string: ")
    iterations = int(input("Enter the number of iterations: "))
    key_sizes = [1024, 2048, 4096]

    results = benchmark_rsa(input_data, iterations, key_sizes)
    display_statistics(results)
    plot_results(results)


