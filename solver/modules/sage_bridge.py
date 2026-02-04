import subprocess
import tempfile
import os
import shutil
import logging
import platform

logger = logging.getLogger(__name__)

def is_wsl_available():
    """Check if 'wsl' executable is in the PATH."""
    return shutil.which("wsl") is not None

def is_sage_available():
    """Check if 'sage' is available (natively or via WSL)."""
    if shutil.which("sage") is not None:
        return "native"
    if is_wsl_available():
        # Check if sage is installed in the default WSL distro
        try:
            subprocess.run(["wsl", "sage", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return "wsl"
        except subprocess.CalledProcessError:
            pass
    return None

def windows_path_to_wsl(path):
    """Convert a Windows path to a WSL path (e.g. C:\\Users -> /mnt/c/Users)."""
    if platform.system() != "Windows":
        return path
    
    # Simple conversion for C: drive, extend if needed or use 'wsl wslpath'
    normalized = os.path.normpath(path).replace("\\", "/")
    if ":" in normalized:
        drive, tail = normalized.split(":", 1)
        return f"/mnt/{drive.lower()}{tail}"
    return path # Fallback

def run_sage_script(script_content, timeout=300):
    """
    Executes a raw SageMath script and returns the output.
    Supports running via WSL on Windows if native sage is missing.
    """
    mode = is_sage_available()
    if not mode:
        error_msg = "SageMath is not installed (checked native and WSL). Please install sage in WSL (Ubuntu): 'sudo apt install sagemath'"
        logger.warning(error_msg)
        raise EnvironmentError(error_msg)

    # Use a temp file accessible to both systems (current dir is usually safe if mounted)
    # We use delete=False to close it before execution
    with tempfile.NamedTemporaryFile(mode='w', suffix='.sage', delete=False, dir=os.getcwd()) as temp_file:
        temp_file.write(script_content)
        temp_path_abs = temp_file.name
    
    try:
        command = []
        if mode == "native":
            command = ["sage", temp_path_abs]
        elif mode == "wsl":
            wsl_path = windows_path_to_wsl(temp_path_abs)
            command = ["wsl", "sage", wsl_path]

        logger.info(f"Executing Sage ({mode}): {' '.join(command)}")
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            logger.error(f"Sage script failed: {result.stderr}")
            raise RuntimeError(f"Sage Error: {result.stderr}\nStdout: {result.stdout}")
            
        return result.stdout.strip()
        
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Sage script execution timed out after {timeout} seconds")
    finally:
        if os.path.exists(temp_path_abs):
            os.remove(temp_path_abs)

if __name__ == "__main__":
    mode = is_sage_available()
    print(f"Sage availability mode: {mode}")
    
    if mode:
        print("Testing calculation 2025 factor...")
        try:
            print(run_sage_script("print(factor(2025))"))
        except Exception as e:
            print(f"Execution failed: {e}")
    else:
        print("Sage not found. If on Windows, try: wsl --install -d Ubuntu ; sudo apt install sagemath")
