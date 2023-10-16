#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <ostream>
#include <unistd.h>

int main()
{
	char filename[100] = "my_test.txt";
	// print pid
	int pid = getpid();
	std::cout << "current pid: " << pid << std::endl;
	system("echo \"hello\" > my_test.txt");
	system("echo \"world\" >> hijacked");
	while (true) {
		std::cout << "Opening my_test.txt" << std::endl;

		int fd = open(filename, O_RDONLY);
		assert(fd != -1);

		std::cout << "test.txt opened, fd=" << fd << std::endl;
		usleep(1000 * 300);
		// print the file content
		char buf[100] = {0};
		int ret = read(fd, buf, 5);
		std::cout << "read " << ret << " bytes: " << buf << std::endl;
		std::cout << "Closing test.txt..." << std::endl;
		close(fd);
		std::cout << "test.txt closed" << std::endl;
	}
	return 0;
}
