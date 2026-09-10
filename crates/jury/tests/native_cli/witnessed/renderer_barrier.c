/* Test-only loader barrier for the real CLI's executable-replacement test. */
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void example_before_main(void) {
    const char *path = getenv("EXAMPLE_IMAGE_READY");
    if (path == NULL) _exit(121);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) _exit(122);
    if (write(fd, "ready", 5) != 5) _exit(123);
    if (close(fd) != 0) _exit(124);
    char release;
    if (read(STDIN_FILENO, &release, 1) != 1 || release != 'x') _exit(125);
}
