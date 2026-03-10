import pytsk3
import sys
import os

class StaticAcquisition:
    def __init__(self, image_path):
        """
        Initializes the static acquisition module using pytsk3.
        It expects a path to a raw disk image or block device.
        """
        self.image_path = image_path
        self.img_info = None
        self.fs_info = None

    def open_image(self):
        """
        Opens the disk image or raw block device non-destructively.
        """
        try:
            # Open the image file at the bit level to ensure zero evidence contamination
            self.img_info = pytsk3.Img_Info(self.image_path)
            print(f"[+] Successfully opened image: {self.image_path}")
            return True
        except IOError as e:
            print(f"[-] Failed to open image: {e}")
            return False

    def load_filesystem(self, offset=0):
        """
        Mounts the filesystem from the disk image at a specific partition offset.
        offset is in bytes (sector_size * starting_sector).
        """
        if not self.img_info:
            print("[-] Image not opened yet.")
            return False

        try:
            self.fs_info = pytsk3.FS_Info(self.img_info, offset=offset)
            print(f"[+] Filesystem loaded at offset {offset}")
            return True
        except IOError as e:
            print(f"[-] Failed to load filesystem at offset {offset}: {e}")
            return False

    def iterate_directory(self, path="/"):
        """
        Recursively iterates over a directory path inside the image and yields file entries.
        """
        if not self.fs_info:
            print("[-] Filesystem not loaded yet.")
            return

        try:
            directory = self.fs_info.open_dir(path)
            for f in directory:
                name = f.info.name.name.decode("utf-8")
                if name in [".", ".."]:
                    continue
                yield f, name
        except IOError as e:
            print(f"[-] Failed to open directory {path}: {e}")

    def read_file_content(self, file_entry):
        """
        Reads the content of a pytsk3 file entry object directly from the disk image.
        Returns a bytearray of the file content.
        """
        if not file_entry.info.meta or not file_entry.info.meta.size:
            return b""
            
        size = file_entry.info.meta.size
        # Reading data at chunk sizes
        CHUNK_SIZE = 1024 * 1024 # 1MB chunks
        file_data = bytearray()
        
        offset = 0
        while offset < size:
            available_to_read = min(CHUNK_SIZE, size - offset)
            try:
                data = file_entry.read_random(offset, available_to_read)
                if not data:
                    break
                file_data.extend(data)
                offset += len(data)
            except IOError as e:
                print(f"[-] Error reading file data: {e}")
                break
                
        return bytes(file_data)

    def extract_file(self, fs_path, destination_path):
        """
        Extracts a file from the image to the local investigation system.
        """
        try:
            file_entry = self.fs_info.open(fs_path)
            content = self.read_file_content(file_entry)
            
            with open(destination_path, "wb") as f_out:
                f_out.write(content)
            print(f"[+] Successfully extracted {fs_path} to {destination_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to extract {fs_path}: {e}")
            return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <image_path>")
        sys.exit(1)
        
    acquisition = StaticAcquisition(sys.argv[1])
    if acquisition.open_image():
        # Attempt to load filesystem at offset 0 (for raw DD images without MBR, or /dev/sdX partitions)
        if acquisition.load_filesystem(0):
            print("[+] Enumerating root directory '/'...")
            for f_entry, name in acquisition.iterate_directory("/"):
                # Identifying file type based on meta type
                if f_entry.info.meta:
                    if f_entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        print(f"  [DIR]  {name}")
                    else:
                        print(f"  [FILE] {name} ({f_entry.info.meta.size} bytes)")
