# main.py
import sys
import subprocess
import platform
import os

def run_command(command):
    """Runs a command in the shell and returns its output."""
    try:
        # Execute the command and capture the output
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.strip(), None
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        # Return the error if the command fails
        return None, str(e)

def print_check(message, status, details=""):
    """Prints a formatted check message."""
    symbol = "✅" if status else "❌"
    print(f"{symbol} {message}")
    if details:
        # Indent details for readability
        print(f"   └── {details}")

def check_python_environment():
    """Checks if the Python version and architecture are compatible."""
    print("\n--- 1. Checking Python Environment ---")
    
    # Check 1: Python Architecture (must be 64-bit)
    is_64bit = platform.architecture()[0] == "64bit"
    print_check("Python is 64-bit", is_64bit, f"Detected: {platform.architecture()[0]}")
    if not is_64bit:
        print("   [SOLUTION] PyTorch requires a 64-bit Python installation. Please uninstall your current Python and reinstall a 64-bit version from python.org.")
    
    # Check 2: Python Version (must be >= 3.8)
    py_version = sys.version_info
    version_str = f"{py_version.major}.{py_version.minor}.{py_version.micro}"
    is_version_ok = py_version >= (3, 8)
    print_check("Python version is compatible (>= 3.8)", is_version_ok, f"Detected: {version_str}")
    if not is_version_ok:
        print("   [SOLUTION] Your Python version is too old. Please upgrade to a newer version (e.g., 3.8, 3.9, 3.10, 3.11).")
        
    return is_64bit and is_version_ok

def check_nvidia_drivers():
    """Checks for NVIDIA drivers using the nvidia-smi command."""
    print("\n--- 2. Checking NVIDIA Driver ---")
    
    # Run nvidia-smi, the standard NVIDIA driver utility
    output, error = run_command("nvidia-smi")
    
    if error:
        print_check("NVIDIA driver is installed and accessible", False, "The 'nvidia-smi' command failed.")
        print(f"   [ERROR] {error}")
        print("   [SOLUTION] This usually means the NVIDIA drivers are not installed correctly or not in your system's PATH. Please download and install the latest drivers for your GPU from the NVIDIA website.")
        return None
        
    # If successful, extract the CUDA version from the output
    driver_cuda_version = "Not Found"
    for line in output.split('\n'):
        if "CUDA Version" in line:
            driver_cuda_version = line.split('CUDA Version:')[1].strip().split()[0]
            break
            
    print_check("NVIDIA driver is installed and accessible", True)
    print_check(f"Driver supports CUDA Version: {driver_cuda_version}", True)
    return driver_cuda_version

def check_pytorch_installation(driver_cuda_version):
    """Checks if PyTorch is installed and compatible with the drivers."""
    print("\n--- 3. Checking PyTorch Installation ---")
    
    # Check 1: Is PyTorch installed?
    try:
        import torch
        print_check("PyTorch is installed", True, f"PyTorch version: {torch.__version__}")
    except ImportError:
        print_check("PyTorch is installed", False)
        print("   [SOLUTION] PyTorch is not installed. Please install it by following the instructions on the official PyTorch website: https://pytorch.org/get-started/locally/")
        return

    # Check 2: Check for potential installation conflicts
    print_check("Checking for installation conflicts", True)
    # Display the exact location of the imported torch library
    print(f"   └── Imported PyTorch from: {os.path.dirname(torch.__file__)}")
    # Warn if running in a Conda environment, a common source of conflicts
    if 'conda' in sys.prefix or 'conda' in os.environ.get('CONDA_DEFAULT_ENV', ''):
        print("   [WARNING] You are in a Conda environment. Ensure you haven't mixed pip and conda for PyTorch installation (e.g., `conda install pytorch` and `pip install torch`). This can cause conflicts. It's best to use one or the other.")


    # Check 3: Was PyTorch built with CUDA support?
    pytorch_cuda_version = torch.version.cuda
    if not pytorch_cuda_version:
        print_check("PyTorch was built with CUDA support", False)
        print("   [SOLUTION] You have installed the CPU-only version of PyTorch. You must uninstall it and reinstall the GPU version.")
        print("   Run this command: pip uninstall torch")
        print("   Then, get the correct installation command from https://pytorch.org/get-started/locally/ (select a CUDA compute platform).")
        return

    print_check(f"PyTorch was built for CUDA {pytorch_cuda_version}", True)
    
    # Check 4: Is the PyTorch CUDA version compatible with the driver?
    if driver_cuda_version:
        # PyTorch is forward-compatible, so the driver version must be >= PyTorch's build version
        try:
            is_compatible = float(driver_cuda_version) >= float(pytorch_cuda_version)
            details = f"Driver CUDA ({driver_cuda_version}) >= PyTorch CUDA ({pytorch_cuda_version})"
            print_check("Driver and PyTorch CUDA versions are compatible", is_compatible, details)
            if not is_compatible:
                print(f"   [SOLUTION] Your NVIDIA driver (for CUDA {driver_cuda_version}) is older than the PyTorch version (for CUDA {pytorch_cuda_version}). Please update your NVIDIA drivers to the latest version.")
        except ValueError:
            print_check("Could not compare CUDA versions", False, "One of the version numbers is not a valid float.")


    # Final Check: Is CUDA available to PyTorch?
    is_available = torch.cuda.is_available()
    print_check("PyTorch can detect and use the GPU", is_available)
    if is_available:
        print(f"   └── Detected GPU: {torch.cuda.get_device_name(0)}")
    else:
        print("   [REASON] This is the final result of the checks above. One of the previous steps failed, preventing PyTorch from using the GPU.")


if __name__ == "__main__":
    print("=========================================")
    print("   CUDA and PyTorch Debugging Tool   ")
    print("=========================================")
    
    if not check_python_environment():
        print("\nCritical Python environment issue found. Please fix it before proceeding.")
        sys.exit(1)
        
    driver_cuda_version = check_nvidia_drivers()
    if not driver_cuda_version:
        print("\nCritical NVIDIA driver issue found. PyTorch cannot function without it.")
        sys.exit(1)
        
    check_pytorch_installation(driver_cuda_version)

    print("\n--- Diagnosis Complete ---")
