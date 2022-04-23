#include "stdlib.h"
#include "syscall.h"
#include <common/ctype.h>
#include <kernel/api/fcntl.h>
#include <stdbool.h>
#include <string.h>

static int read_line(char* out_cmd) {
    size_t len = 0;
    for (;;) {
        char c;
        ssize_t nread = read(0, &c, 1);
        if (nread < 0)
            return -1;
        if (nread == 0)
            continue;
        switch (c) {
        case '\r':
        case '\n':
            out_cmd[len] = '\0';
            return 0;
        case '\b':
        case '\x7f': // ^H
            if (len == 0)
                continue;
            out_cmd[--len] = '\0';
            printf("\b \b");
            break;
        case 'U' - '@': // ^U
            memset(out_cmd, 0, len);
            for (; len > 0; --len)
                printf("\b \b");
            break;
        case '\t':
            break;
        case 'D' - '@': // ^D
            if (len == 0) {
                strcpy(out_cmd, "exit");
                return 0;
            }
            break;
        default:
            out_cmd[len++] = c;
            putchar(c);
            break;
        }
    }
}

#define MAX_ARGC 16

struct node {
    enum {
        CMD_EXECUTE,
        CMD_JUXTAPOSITION,
        CMD_PIPE,
        CMD_REDIRECT,
        CMD_BACKGROUND
    } type;

    union {
        struct execute_node {
            char* argv[MAX_ARGC];
            size_t lengths[MAX_ARGC];
        } execute;

        struct juxtaposition_node {
            struct node* left;
            struct node* right;
        } juxtaposition;

        struct pipe_node {
            struct node* left;
            struct node* right;
        } pipe;

        struct redirect_node {
            struct node* from;
            char* to;
            size_t to_length;
        } redirect;

        struct background_node {
            struct node* inner;
        } background;
    };
};

struct parser {
    char* cursor;
    enum {
        RESULT_SUCCESS,
        RESULT_EMPTY,
        RESULT_NOMEM_ERROR,
        RESULT_SYNTAX_ERROR,
        RESULT_TOO_MANY_ARGS_ERROR
    } result;
};

static char peek(struct parser* parser) { return *parser->cursor; }

static char consume(struct parser* parser) { return *parser->cursor++; }

static bool consume_if(struct parser* parser, char c) {
    if (*parser->cursor == c) {
        consume(parser);
        return true;
    }
    return false;
}

static char* consume_while(struct parser* parser, bool (*cond)(char)) {
    if (!*parser->cursor || !cond(*parser->cursor))
        return NULL;
    char* start = parser->cursor;
    do {
        ++parser->cursor;
    } while (cond(peek(parser)));
    return start;
}

static bool is_whitespace(char c) { return isspace(c); }

static void skip_whitespaces(struct parser* parser) {
    consume_while(parser, is_whitespace);
}

static bool is_valid_filename_character(char c) {
    switch (c) {
    case '>':
    case ' ':
    case '|':
    case '&':
    case ';':
        return false;
    }
    return ' ' <= c && c <= '~';
}

static char* parse_filename(struct parser* parser) {
    return consume_while(parser, is_valid_filename_character);
}

static struct node* parse_execute(struct parser* parser) {
    struct node* node = malloc(sizeof(struct node));
    if (!node) {
        parser->result = RESULT_NOMEM_ERROR;
        return NULL;
    }
    node->type = CMD_EXECUTE;

    struct execute_node* execute = &node->execute;
    size_t i = 0;
    for (;; ++i) {
        if (i >= MAX_ARGC) {
            parser->result = RESULT_TOO_MANY_ARGS_ERROR;
            return NULL;
        }
        char* arg = parse_filename(parser);
        if (!arg)
            break;
        char* saved_cursor = parser->cursor;
        skip_whitespaces(parser);
        execute->argv[i] = arg;
        execute->lengths[i] = saved_cursor - arg;
    }
    if (i == 0) {
        parser->result = RESULT_EMPTY;
        return NULL;
    }

    return node;
}

static struct node* parse_redirect(struct parser* parser) {
    struct node* from = parse_execute(parser);
    if (!from)
        return NULL;
    skip_whitespaces(parser);
    if (!consume_if(parser, '>'))
        return from;
    skip_whitespaces(parser);

    char* to = parse_filename(parser);
    if (!to) {
        parser->result = RESULT_SYNTAX_ERROR;
        return NULL;
    }

    struct node* node = malloc(sizeof(struct node));
    if (!node) {
        parser->result = RESULT_NOMEM_ERROR;
        return NULL;
    }
    node->type = CMD_REDIRECT;

    struct redirect_node* redirect = &node->redirect;
    redirect->from = from;
    redirect->to = to;
    redirect->to_length = parser->cursor - to;
    return node;
}

static struct node* parse_pipe(struct parser* parser) {
    struct node* left = parse_redirect(parser);
    if (!left)
        return NULL;
    skip_whitespaces(parser);
    if (!consume_if(parser, '|'))
        return left;
    skip_whitespaces(parser);

    struct node* right = parse_pipe(parser);
    if (!right) {
        if (parser->result == RESULT_EMPTY)
            parser->result = RESULT_SYNTAX_ERROR;
        return NULL;
    }

    struct node* node = malloc(sizeof(struct node));
    if (!node) {
        parser->result = RESULT_NOMEM_ERROR;
        return NULL;
    }
    node->type = CMD_PIPE;

    struct pipe_node* pipe = &node->pipe;
    pipe->left = left;
    pipe->right = right;
    return node;
}

static struct node* parse_juxtaposition(struct parser* parser) {
    struct node* left = parse_pipe(parser);
    if (!left)
        return NULL;
    skip_whitespaces(parser);

    if (consume_if(parser, '&')) {
        struct node* bg = malloc(sizeof(struct node));
        if (!bg) {
            parser->result = RESULT_NOMEM_ERROR;
            return NULL;
        }
        bg->type = CMD_BACKGROUND;
        bg->background.inner = left;
        left = bg;
    } else if (!consume_if(parser, ';')) {
        return left;
    }
    skip_whitespaces(parser);

    struct node* right = parse_juxtaposition(parser);
    if (!right) {
        if (parser->result == RESULT_EMPTY)
            parser->result = RESULT_SUCCESS;
        return left;
    }

    struct node* node = malloc(sizeof(struct node));
    if (!node) {
        parser->result = RESULT_NOMEM_ERROR;
        return NULL;
    }
    node->type = CMD_JUXTAPOSITION;

    struct juxtaposition_node* jux = &node->juxtaposition;
    jux->left = left;
    jux->right = right;
    return node;
}

static void null_terminate(struct node* node) {
    switch (node->type) {
    case CMD_EXECUTE: {
        char** argv = node->execute.argv;
        size_t* length = node->execute.lengths;
        while (*argv)
            (*argv++)[*length++] = 0;
        return;
    }
    case CMD_JUXTAPOSITION:
        null_terminate(node->juxtaposition.left);
        null_terminate(node->juxtaposition.right);
        return;
    case CMD_PIPE:
        null_terminate(node->pipe.left);
        null_terminate(node->pipe.right);
        return;
    case CMD_REDIRECT:
        null_terminate(node->redirect.from);
        (node->redirect.to)[node->redirect.to_length] = 0;
        return;
    case CMD_BACKGROUND:
        null_terminate(node->background.inner);
        return;
    }
    UNREACHABLE();
}

static struct node* parse(struct parser* parser, char* line) {
    parser->cursor = line;
    parser->result = RESULT_SUCCESS;

    skip_whitespaces(parser);
    struct node* node = parse_juxtaposition(parser);
    skip_whitespaces(parser);
    if (peek(parser) != 0) {
        parser->result = RESULT_SYNTAX_ERROR;
        return NULL;
    }
    if (!node)
        return NULL;

    if (node)
        null_terminate(node);
    return node;
}

static int run_command(const struct node* node, char* const envp[]);

static int run_execute(const struct execute_node* node, char* const envp[]) {
    if (!strcmp(node->argv[0], "exit")) {
        puts("exit");
        exit(0);
    }
    if (!strcmp(node->argv[0], "cd")) {
        if (node->argv[1])
            return chdir(node->argv[1]);
        const char* home = getenv("HOME");
        if (home)
            return chdir(home);
        return 0;
    }

    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (execvpe(node->argv[0], node->argv, envp) < 0) {
            perror("execvpe");
            abort();
        }
        UNREACHABLE();
    }
    return waitpid(pid, NULL, 0);
}

static int run_juxtaposition(const struct juxtaposition_node* node,
                             char* const envp[]) {
    if (run_command(node->left, envp) < 0)
        return -1;
    return run_command(node->right, envp);
}

static int run_pipe(const struct pipe_node* node, char* const envp[]) {
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        dup2(pipefd[1], 1);
        close(pipefd[0]);
        close(pipefd[1]);
        if (run_command(node->left, envp) < 0) {
            perror("run_command");
            abort();
        }
        close(1);
        exit(EXIT_SUCCESS);
    }

    int saved_stdin = dup(0);
    dup2(pipefd[0], 0);
    close(pipefd[0]);
    close(pipefd[1]);
    if (run_command(node->right, envp) < 0) {
        dup2(saved_stdin, 0);
        close(saved_stdin);
        return -1;
    }
    dup2(saved_stdin, 0);
    close(saved_stdin);

    return waitpid(pid, NULL, 0);
}

static int run_redirect(const struct redirect_node* node, char* const envp[]) {
    int fd = open(node->to, O_WRONLY | O_CREAT, 0);
    if (fd < 0)
        return -1;
    int saved_stdout = dup(1);
    dup2(fd, 1);
    close(fd);
    if (run_command(node->from, envp) < 0) {
        dup2(saved_stdout, 1);
        close(saved_stdout);
        return -1;
    }
    dup2(saved_stdout, 1);
    close(saved_stdout);
    return 0;
}

static int run_background(const struct background_node* node,
                          char* const envp[]) {
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (run_command(node->inner, envp) < 0) {
            perror("run_command");
            abort();
        }
        exit(EXIT_SUCCESS);
    }
    return 0;
}

static int run_command(const struct node* node, char* const envp[]) {
    switch (node->type) {
    case CMD_EXECUTE:
        return run_execute(&node->execute, envp);
    case CMD_JUXTAPOSITION:
        return run_juxtaposition(&node->juxtaposition, envp);
    case CMD_PIPE:
        return run_pipe(&node->pipe, envp);
    case CMD_REDIRECT:
        return run_redirect(&node->redirect, envp);
    case CMD_BACKGROUND:
        return run_background(&node->background, envp);
    }
    UNREACHABLE();
}

#define BUF_SIZE 1024

int main(int argc, char* const argv[], char* const envp[]) {
    (void)argc;
    (void)argv;

    for (;;) {
        static char buf[BUF_SIZE];
        memset(buf, 0, BUF_SIZE);
        getcwd(buf, 1024);
        printf("\x1b[36m%s\x1b[m $ ", buf);

        memset(buf, 0, BUF_SIZE);
        if (read_line(buf) < 0) {
            perror("read_line");
            return EXIT_FAILURE;
        }
        putchar('\n');

        static struct parser parser;
        struct node* node = parse(&parser, buf);
        switch (parser.result) {
        case RESULT_SUCCESS:
            ASSERT(node);
            break;
        case RESULT_EMPTY:
            continue;
        case RESULT_NOMEM_ERROR:
            dprintf(2, "Out of memory\n");
            return EXIT_FAILURE;
        case RESULT_SYNTAX_ERROR:
            dprintf(2, "Syntax error\n");
            continue;
        case RESULT_TOO_MANY_ARGS_ERROR:
            dprintf(2, "Too many arguments\n");
            continue;
        default:
            UNREACHABLE();
        }

        if (run_command(node, envp) < 0)
            perror("run_command");
    }
    return EXIT_SUCCESS;
}
