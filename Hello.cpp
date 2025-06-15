#include <iostream>
#include <fstream>
#include <Windows.h>
#include <vector>
using namespace std;
class Encryption
{
public:
	void EncryptPEHeader(const std::string& TargetPath) {
		ProcessHeader(TargetPath, true);
	}
	void DecryptPEHeader(const std::string& TargetPath) {
		ProcessHeader(TargetPath, false);
	}
	std::vector<uint8_t> MemoryDecryptPE(const std::string& TargetPath) {
		std::ifstream file(TargetPath, std::ios::binary);
		if (!file.is_open()) {
			std::cout << "[!] Failed to open file: " << TargetPath << std::endl;
			return {};
		}
		std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(file)), {});
		file.close();
		for (size_t i = 0; i < this->headerSize && i < buffer.size(); ++i)
			buffer[i] ^= this->XorKey;
		return buffer;
	}
private:
	DWORD XorKey = 0x5ACF;
	const DWORD headerSize = 0x1000;
	void ProcessHeader(const std::string& path, bool encrypt) {
		std::fstream file(path, std::ios::in | std::ios::out | std::ios::binary);
		if (!file.is_open()) {
			std::cout << "[!] Failed to open file: " << path << std::endl;
			return;
		}

		std::vector<char> buffer(this->headerSize);
		file.read(buffer.data(), this->headerSize);
		std::streamsize bytesRead = file.gcount();
		file.clear();
		if (bytesRead <= 0) {
			std::cout << "[!] Failed to read file.\n";
			return;
		}
		for (std::streamsize i = 0; i < bytesRead; ++i)
			buffer[i] ^= XorKey;

		file.seekp(0, std::ios::beg);
		file.write(buffer.data(), bytesRead);
		file.close();
		std::cout << "[+] " << (encrypt ? "Encrypted" : "Decrypted") << " PE header (" << bytesRead << " bytes) successfully.\n";
	}
};



int main(int argc, char* argv[]) {
	if (argc != 3) {
		cout << "Usage: Encrypter.exe <TargetFile> <Encrypt|Decrypt>\n";
		return 1;
	}
	Encryption tool;
	std::string action = argv[2];
	if (action == "Encrypt") {
		tool.EncryptPEHeader(argv[1]);
	}
	else if (action == "Decrypt") {
		tool.DecryptPEHeader(argv[1]);
	}
	return 0;
}
