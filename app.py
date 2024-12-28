from flask import Flask, request, render_template
import time
import tracemalloc
import os
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding

import matplotlib
matplotlib.use('Agg')  # Use a non-GUI backend for rendering images
import matplotlib.pyplot as plt


app = Flask(__name__)

# RSA Functions
def generate_rsa_key(key_size):
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        rsa_padding.OAEP(
            mgf= rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf= rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def benchmark_rsa(input_data, key_size, iterations):
    private_key = generate_rsa_key(key_size)
    public_key = private_key.public_key()

    encryption_times = []
    decryption_times = []
    encryption_memories = []
    decryption_memories = []

    for _ in range(iterations):
        tracemalloc.start()
        start_time = time.time()
        ciphertext = rsa_encrypt(public_key, input_data)
        encryption_time = time.time() - start_time
        encryption_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        tracemalloc.start()
        start_time = time.time()
        decrypted_text = rsa_decrypt(private_key, ciphertext)
        decryption_time = time.time() - start_time
        decryption_memory = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        # Verify correctness
        assert input_data == decrypted_text, "Decryption failed!"

        # Record stats
        encryption_times.append(encryption_time)
        decryption_times.append(decryption_time)
        encryption_memories.append(encryption_memory[1])
        decryption_memories.append(decryption_memory[1])

    # Aggregate results
    return {
        "key_size": key_size,
        "iterations": iterations,
        "avg_enc_time": sum(encryption_times) / iterations,
        "avg_dec_time": sum(decryption_times) / iterations,
        "enc_throughput": iterations / sum(encryption_times),
        "dec_throughput": iterations / sum(decryption_times),
        "avg_enc_memory": sum(encryption_memories) / iterations,
        "avg_dec_memory": sum(decryption_memories) / iterations,
        "input_size": len(input_data),
    }

def plot_results(results, input_size):
    key_sizes = [res['key_size'] for res in results]
    enc_times = [res['avg_enc_time'] for res in results]
    dec_times = [res['avg_dec_time'] for res in results]
    enc_memories = [res['avg_enc_memory'] for res in results]
    dec_memories = [res['avg_dec_memory'] for res in results]
    enc_throughput = [res['enc_throughput'] for res in results]
    dec_throughput = [res['dec_throughput'] for res in results]

    fig, axs = plt.subplots(3, 1, figsize=(10, 15))

    # Encryption and Decryption Times
    axs[0].plot(key_sizes, enc_times, marker='o', label='Encryption Time')
    axs[0].plot(key_sizes, dec_times, marker='o', label='Decryption Time')
    axs[0].set_title(f'RSA Encryption and Decryption Times\n(Input Size: {input_size} bytes)')
    axs[0].set_xlabel('Key Size (bits)')
    axs[0].set_ylabel('Time (s)')
    axs[0].legend()
    axs[0].grid(True)

    # Memory Usage
    axs[1].plot(key_sizes, enc_memories, marker='o', label='Encryption Memory')
    axs[1].plot(key_sizes, dec_memories, marker='o', label='Decryption Memory')
    axs[1].set_title(f'RSA Memory Usage\n(Input Size: {input_size} bytes)')
    axs[1].set_xlabel('Key Size (bits)')
    axs[1].set_ylabel('Memory (bytes)')
    axs[1].legend()
    axs[1].grid(True)

    # Throughput
    axs[2].plot(key_sizes, enc_throughput, marker='o', label='Encryption Throughput')
    axs[2].plot(key_sizes, dec_throughput, marker='o', label='Decryption Throughput')
    axs[2].set_title(f'RSA Throughput\n(Input Size: {input_size} bytes)')
    axs[2].set_xlabel('Key Size (bits)')
    axs[2].set_ylabel('Throughput (ops/sec)')
    axs[2].legend()
    axs[2].grid(True)

    plt.tight_layout()
    graph_filename = f"rsa_benchmark_{input_size}.png"  # Unique filename for each input size
    graph_path = os.path.join("static", graph_filename)
    plt.savefig(graph_path)  # Save graph in static folder
    plt.close(fig)  # Free memory
    return graph_filename


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        input_data = request.form.get('input_data')
        uploaded_file = request.files.get('file_input')
        iterations = int(request.form.get('iterations'))

        # Handle file input
        if uploaded_file and uploaded_file.filename:
            input_data = uploaded_file.read()  # Read the file content as bytes
        elif input_data:
            input_data = input_data.encode()  # Encode the string input to bytes
        else:
            error_message = "Please provide either text input or upload a file."
            return render_template('index.html', error_message=error_message)

        input_size = len(input_data)

        # Run RSA Benchmark
        key_sizes = [1024, 2048, 4096]
        results = []
        for key_size in key_sizes:
            results.append(benchmark_rsa(input_data, key_size, iterations))

        # Generate graph based on input size
        graph_filename = plot_results(results, input_size)

        # Render template with results and graph filename
        return render_template(
            'index.html',
            results=results,
            input_size=input_size,
            graph_filename=graph_filename,
            error_message=None
        )

    return render_template('index.html', results=None, input_size=None, graph_filename=None, error_message=None)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5003, debug=False)
