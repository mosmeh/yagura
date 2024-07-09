#include <ctype.h>
#include <dirent.h>
#include <extra.h>
#include <fcntl.h>
#include <panic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#define BUF_SIZE 1024

struct history_entry {
    char line[BUF_SIZE];
    struct history_entry* prev;
    struct history_entry* next;
};

struct line_editor {
    struct termios default_termios;

    char input_buf[BUF_SIZE];
    size_t input_len;
    size_t cursor;

    enum { STATE_GROUND, STATE_ESC, STATE_CSI, STATE_ACCEPTED } state;
    bool dirty;

    char param_buf[BUF_SIZE];
    size_t param_len;

    struct history_entry* history_head;
    struct history_entry* history_tail;
    struct history_entry* history_cursor;
};

static bool starts_with(const char* str, size_t str_len, const char* prefix,
                        size_t prefix_len) {
    for (size_t i = 0; i < prefix_len; ++i) {
        if (i >= str_len || str[i] != prefix[i])
            return false;
    }
    return true;
}

static bool complete_entries_in_dir(struct line_editor* ed, const char* word,
                                    size_t word_len, const char* path) {
    DIR* dirp = opendir(path);
    if (!dirp)
        return false;

    struct dirent* dent;
    while ((dent = readdir(dirp))) {
        if (dent->d_namlen <= word_len)
            continue;
        if (!starts_with(dent->d_name, dent->d_namlen, word, word_len))
            continue;

        size_t completed_len = dent->d_namlen - word_len;
        memmove(ed->input_buf + ed->cursor + completed_len,
                ed->input_buf + ed->cursor, ed->input_len - ed->cursor);
        memcpy(ed->input_buf + ed->cursor, dent->d_name + word_len,
               completed_len);
        ed->input_len += completed_len;
        ed->cursor += completed_len;

        closedir(dirp);
        return true;
    }

    closedir(dirp);
    return false;
}

static bool is_valid_filename_character(char c) {
    return isgraph(c) && c != '/';
}

static bool complete(struct line_editor* ed) {
    if (ed->cursor == 0 ||
        !is_valid_filename_character(ed->input_buf[ed->cursor - 1]))
        return false;
    if (ed->cursor != ed->input_len && ed->input_buf[ed->cursor] != ' ')
        return false;

    char* word = ed->input_buf + ed->cursor - 1;
    size_t word_len = 1;
    while (word > ed->input_buf && is_valid_filename_character(*(word - 1))) {
        --word;
        ++word_len;
    }

    if (word > ed->input_buf && *(word - 1) == '/') {
        char* dir = word - 1;
        size_t dir_len = 1;
        while (dir > ed->input_buf && isgraph(*(dir - 1))) {
            --dir;
            ++dir_len;
        }

        char* null_terminated_dir = malloc((dir_len + 1) * sizeof(char));
        if (!null_terminated_dir)
            return false;
        memcpy(null_terminated_dir, dir, dir_len);
        null_terminated_dir[dir_len] = 0;
        bool completed =
            complete_entries_in_dir(ed, word, word_len, null_terminated_dir);
        free(null_terminated_dir);
        return completed;
    }

    if (complete_entries_in_dir(ed, word, word_len, "."))
        return true;

    const char* path = getenv("PATH");
    if (!path)
        return false;
    char* dup_path = strdup(path);
    if (!dup_path)
        return false;

    static const char* sep = ":";
    char* saved_ptr;
    for (const char* part = strtok_r(dup_path, sep, &saved_ptr); part;
         part = strtok_r(NULL, sep, &saved_ptr)) {
        if (complete_entries_in_dir(ed, word, word_len, part)) {
            free(dup_path);
            return true;
        }
    }
    free(dup_path);

    return false;
}

static void on_left(struct line_editor* ed) {
    if (ed->cursor > 0) {
        --ed->cursor;
        ed->dirty = true;
    }
}

static void on_right(struct line_editor* ed) {
    if (ed->cursor < ed->input_len) {
        ++ed->cursor;
        ed->dirty = true;
    }
}

static void on_home(struct line_editor* ed) {
    ed->cursor = 0;
    ed->dirty = true;
}

static void on_end(struct line_editor* ed) {
    ed->cursor = ed->input_len;
    ed->dirty = true;
}

static void on_up(struct line_editor* ed) {
    if (!ed->history_cursor)
        ed->history_cursor = ed->history_tail;
    else if (ed->history_cursor->prev)
        ed->history_cursor = ed->history_cursor->prev;
    if (ed->history_cursor) {
        memcpy(ed->input_buf, ed->history_cursor->line, BUF_SIZE);
        ed->input_len = ed->cursor = strlen(ed->input_buf);
        ed->dirty = true;
    }
}

static void on_down(struct line_editor* ed) {
    if (ed->history_cursor) {
        ed->history_cursor = ed->history_cursor->next;
        if (ed->history_cursor)
            memcpy(ed->input_buf, ed->history_cursor->line, BUF_SIZE);
        else
            memset(ed->input_buf, 0, BUF_SIZE);
        ed->input_len = ed->cursor = strlen(ed->input_buf);
        ed->dirty = true;
    }
}

static void on_delete(struct line_editor* ed) {
    if (ed->cursor < ed->input_len) {
        memmove(ed->input_buf + ed->cursor, ed->input_buf + ed->cursor + 1,
                ed->input_len - ed->cursor - 1);
        ed->input_buf[--ed->input_len] = 0;
        ed->dirty = true;
    }
}

static void handle_ground(struct line_editor* ed, char c) {
    if (isprint(c)) {
        memmove(ed->input_buf + ed->cursor + 1, ed->input_buf + ed->cursor,
                ed->input_len - ed->cursor);
        ed->input_buf[ed->cursor++] = c;
        ++ed->input_len;
        ed->dirty = true;
        return;
    }
    switch (c) {
    case '\x1b':
        ed->state = STATE_ESC;
        return;
    case '\r':
    case '\n':
        ed->state = STATE_ACCEPTED;
        return;
    case 'B' - '@': // ^B
        on_left(ed);
        return;
    case 'F' - '@': // ^F
        on_right(ed);
        return;
    case 'A' - '@': // ^A
        on_home(ed);
        return;
    case 'E' - '@': // ^E
        on_end(ed);
        return;
    case 'P' - '@': // ^P
        on_up(ed);
        return;
    case 'N' - '@': // ^N
        on_down(ed);
        return;
    case '\b': // ^H
    case '\x7f':
        if (ed->cursor == 0)
            return;
        memmove(ed->input_buf + ed->cursor - 1, ed->input_buf + ed->cursor,
                ed->input_len - ed->cursor);
        ed->input_buf[--ed->input_len] = 0;
        --ed->cursor;
        ed->dirty = true;
        return;
    case 'U' - '@': // ^U
        memmove(ed->input_buf, ed->input_buf + ed->cursor,
                ed->input_len - ed->cursor);
        memset(ed->input_buf + ed->input_len - ed->cursor, 0, ed->cursor);
        ed->input_len -= ed->cursor;
        ed->cursor = 0;
        ed->dirty = true;
        return;
    case 'K' - '@': // ^K
        memset(ed->input_buf + ed->cursor, 0, ed->input_len - ed->cursor);
        ed->input_len = ed->cursor;
        ed->dirty = true;
        return;
    case 'D' - '@': // ^D
        if (ed->input_len == 0) {
            strcpy(ed->input_buf, "exit");
            ed->state = STATE_ACCEPTED;
            ed->dirty = true;
        } else {
            on_delete(ed);
        }
        return;
    case 'L' - '@': // ^L
        dprintf(STDERR_FILENO, "\x1b[H\x1b[2J");
        ed->dirty = true;
        return;
    case '\t':
        if (complete(ed))
            ed->dirty = true;
        return;
    }
}

static void handle_state_esc(struct line_editor* ed, char c) {
    switch (c) {
    case '[':
        ed->param_len = 0;
        ed->state = STATE_CSI;
        return;
    }
    ed->state = STATE_GROUND;
    handle_ground(ed, c);
}

static void handle_csi_vt(struct line_editor* ed) {
    int code = atoi(ed->param_buf);
    switch (code) {
    case 1:
    case 7:
        on_home(ed);
        return;
    case 4:
    case 8:
        on_end(ed);
        return;
    case 3:
        on_delete(ed);
        return;
    }
}

static void handle_state_csi(struct line_editor* ed, char c) {
    if (c < 0x40) {
        ed->param_buf[ed->param_len++] = c;
        return;
    }
    ed->param_buf[ed->param_len] = '\0';

    switch (c) {
    case 'A':
        on_up(ed);
        break;
    case 'B':
        on_down(ed);
        break;
    case 'C':
        on_right(ed);
        break;
    case 'D':
        on_left(ed);
        break;
    case 'H':
        on_home(ed);
        break;
    case 'F':
        on_end(ed);
        break;
    case '~':
        handle_csi_vt(ed);
        break;
    }

    ed->state = STATE_GROUND;
}

static void on_char(struct line_editor* ed, char c) {
    switch (ed->state) {
    case STATE_GROUND:
        handle_ground(ed, c);
        return;
    case STATE_ESC:
        handle_state_esc(ed, c);
        return;
    case STATE_CSI:
        handle_state_csi(ed, c);
        return;
    default:
        UNREACHABLE();
    }
}

static char* read_input(struct line_editor* ed, size_t terminal_width) {
    ed->state = STATE_GROUND;
    memset(ed->input_buf, 0, BUF_SIZE);
    ed->input_len = ed->cursor = 0;
    ed->dirty = true;

    char cwd_buf[BUF_SIZE];
    memset(cwd_buf, 0, BUF_SIZE);
    getcwd(cwd_buf, 1024);

    size_t prompt_len = strlen(cwd_buf) + 3;

    struct termios termios = ed->default_termios;
    termios.c_lflag &= ~(ICANON | ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &termios) < 0) {
        perror("tcsetattr");
        return NULL;
    }

    for (;;) {
        if (ed->dirty) {
            dprintf(STDERR_FILENO,
                    "\x1b[?25l"            // hide cursor
                    "\x1b[G"               // go to left end
                    "\x1b[36m%s\x1b[m $ ", // print prompt
                    cwd_buf);

            bool clear_needed = prompt_len + ed->input_len < terminal_width;
            size_t cursor_x = prompt_len + ed->cursor;

            if (cursor_x < terminal_width) {
                size_t len = MIN(ed->input_len, terminal_width - prompt_len);
                write(STDERR_FILENO, ed->input_buf, len);
            } else {
                const char* str = ed->input_buf + cursor_x - terminal_width + 1;
                size_t len =
                    MIN(ed->input_len, terminal_width - prompt_len + 1) - 1;
                if (ed->cursor == ed->input_len && cursor_x > terminal_width) {
                    --len;
                    clear_needed = true;
                }
                cursor_x = terminal_width;
                write(STDERR_FILENO, str, len);
            }

            if (clear_needed)
                dprintf(STDERR_FILENO, "\x1b[J"); // clear from cursor to end

            dprintf(STDERR_FILENO,
                    "\x1b[%uG"   // set cursor position
                    "\x1b[?25h", // show cursor
                    cursor_x + 1);
            ed->dirty = false;
        }

        char c;
        ssize_t nread = read(STDIN_FILENO, &c, 1);
        if (nread < 0) {
            perror("read");
            return NULL;
        }
        if (nread == 0)
            break;
        on_char(ed, c);

        if (ed->state == STATE_ACCEPTED)
            break;
    }

    if (tcsetattr(STDIN_FILENO, TCSANOW, &ed->default_termios) < 0)
        perror("tcsetattr");

    struct history_entry* entry = malloc(sizeof(struct history_entry));
    if (!entry) {
        perror("malloc");
        return NULL;
    }
    *entry = (struct history_entry){0};
    memcpy(entry->line, ed->input_buf, BUF_SIZE);

    if (!ed->history_head) {
        ed->history_head = ed->history_tail = entry;
    } else {
        entry->prev = ed->history_tail;
        ed->history_tail->next = entry;
        ed->history_tail = entry;
    }
    ed->history_cursor = NULL;

    return ed->input_buf;
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
            struct node* inner;
            char* pathname;
            size_t pathname_length;
            bool is_write;
            int fd;
        } redirect;

        struct background_node {
            struct node* inner;
        } background;
    };
};

static void destroy_node(struct node* node) {
    if (!node)
        return;
    switch (node->type) {
    case CMD_EXECUTE:
        break;
    case CMD_JUXTAPOSITION:
        destroy_node(node->juxtaposition.left);
        destroy_node(node->juxtaposition.right);
        break;
    case CMD_PIPE:
        destroy_node(node->pipe.left);
        destroy_node(node->pipe.right);
        break;
    case CMD_REDIRECT:
        destroy_node(node->redirect.inner);
        break;
    case CMD_BACKGROUND:
        destroy_node(node->background.inner);
        break;
    default:
        UNREACHABLE();
    }
    free(node);
}

struct parser {
    char* cursor;
    enum {
        PARSE_SUCCESS,
        PARSE_EMPTY,
        PARSE_NOMEM_ERROR,
        PARSE_SYNTAX_ERROR,
        PARSE_TOO_MANY_ARGS_ERROR
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

static bool is_valid_pathname_character(char c) {
    switch (c) {
    case '>':
    case '<':
    case ' ':
    case '|':
    case '&':
    case ';':
        return false;
    }
    return isgraph(c);
}

static char* parse_pathname(struct parser* parser) {
    return consume_while(parser, is_valid_pathname_character);
}

static struct node* parse_execute(struct parser* parser) {
    struct node* node = malloc(sizeof(struct node));
    if (!node) {
        parser->result = PARSE_NOMEM_ERROR;
        return NULL;
    }
    node->type = CMD_EXECUTE;

    struct execute_node* execute = &node->execute;
    size_t i = 0;
    for (;; ++i) {
        if (i >= MAX_ARGC) {
            parser->result = PARSE_TOO_MANY_ARGS_ERROR;
            free(node);
            return NULL;
        }
        char* arg = parse_pathname(parser);
        if (!arg)
            break;
        char* saved_cursor = parser->cursor;
        skip_whitespaces(parser);
        execute->argv[i] = arg;
        execute->lengths[i] = saved_cursor - arg;
    }
    if (i == 0) {
        parser->result = PARSE_EMPTY;
        free(node);
        return NULL;
    }

    return node;
}

static struct node* parse_redirect(struct parser* parser) {
    struct node* inner = parse_execute(parser);
    if (!inner)
        return NULL;
    skip_whitespaces(parser);

    for (;;) {
        char maybe_fd = peek(parser);
        int fd = -1;
        if (isdigit(maybe_fd)) {
            fd = maybe_fd - '0';
            consume(parser);
        }

        bool is_write = consume_if(parser, '>');
        if (!is_write && !consume_if(parser, '<')) {
            return inner;
        }
        skip_whitespaces(parser);

        char* pathname = parse_pathname(parser);
        if (!pathname) {
            parser->result = PARSE_SYNTAX_ERROR;
            destroy_node(inner);
            return NULL;
        }

        struct node* node = malloc(sizeof(struct node));
        if (!node) {
            parser->result = PARSE_NOMEM_ERROR;
            destroy_node(inner);
            return NULL;
        }
        node->type = CMD_REDIRECT;

        struct redirect_node* redirect = &node->redirect;
        redirect->inner = inner;
        redirect->pathname = pathname;
        redirect->pathname_length = parser->cursor - pathname;
        redirect->is_write = is_write;
        redirect->fd = fd;

        inner = node;
        skip_whitespaces(parser);
    }
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
        if (parser->result == PARSE_EMPTY)
            parser->result = PARSE_SYNTAX_ERROR;
        destroy_node(left);
        return NULL;
    }

    struct node* node = malloc(sizeof(struct node));
    if (!node) {
        parser->result = PARSE_NOMEM_ERROR;
        destroy_node(right);
        destroy_node(left);
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
            parser->result = PARSE_NOMEM_ERROR;
            destroy_node(left);
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
        if (parser->result == PARSE_EMPTY)
            parser->result = PARSE_SUCCESS;
        return left;
    }

    struct node* node = malloc(sizeof(struct node));
    if (!node) {
        parser->result = PARSE_NOMEM_ERROR;
        destroy_node(right);
        destroy_node(left);
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
        null_terminate(node->redirect.inner);
        (node->redirect.pathname)[node->redirect.pathname_length] = 0;
        return;
    case CMD_BACKGROUND:
        null_terminate(node->background.inner);
        return;
    }
    UNREACHABLE();
}

static struct node* parse(struct parser* parser, char* line) {
    parser->cursor = line;
    parser->result = PARSE_SUCCESS;

    skip_whitespaces(parser);
    struct node* node = parse_juxtaposition(parser);
    skip_whitespaces(parser);
    if (peek(parser) != 0) {
        parser->result = PARSE_SYNTAX_ERROR;
        destroy_node(node);
        return NULL;
    }
    if (!node)
        return NULL;
    null_terminate(node);

    return node;
}

enum {
    RUN_ERROR = -1,
    RUN_SIGNALED = -2,
};

struct run_context {
    pid_t pgid;
    bool foreground;
};

static int run_command(const struct node* node, struct run_context ctx);

static int run_execute(const struct execute_node* node,
                       struct run_context ctx) {
    if (!strcmp(node->argv[0], "exit")) {
        dprintf(STDERR_FILENO, "exit\n");
        int status = node->argv[1] ? atoi(node->argv[1]) : 0;
        exit(status);
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
    if (pid < 0) {
        perror("fork");
        return RUN_ERROR;
    }
    if (pid == 0) {
        if (!ctx.pgid)
            ctx.pgid = getpid();
        if (setpgid(0, ctx.pgid) < 0) {
            perror("setpgpid");
            abort();
        }
        if (ctx.foreground)
            tcsetpgrp(STDIN_FILENO, ctx.pgid);
        if (execvpe(node->argv[0], node->argv, environ) < 0) {
            perror("execvpe");
            abort();
        }
        UNREACHABLE();
    }

    int wstatus = 0;
    if (waitpid(pid, &wstatus, 0) < 0) {
        perror("waitpid");
        return RUN_ERROR;
    }
    if (WIFSIGNALED(wstatus))
        return RUN_SIGNALED;

    return 0;
}

static int run_juxtaposition(const struct juxtaposition_node* node,
                             struct run_context ctx) {
    int rc = run_command(node->left, ctx);
    if (rc < 0)
        return rc;
    return run_command(node->right, ctx);
}

static int run_pipe(const struct pipe_node* node, struct run_context ctx) {
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return RUN_ERROR;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return RUN_ERROR;
    }
    if (pid == 0) {
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        if (!ctx.pgid)
            ctx.pgid = getpid();
        if (run_command(node->left, ctx) == RUN_ERROR)
            abort();

        close(STDOUT_FILENO);
        exit(EXIT_SUCCESS);
    }

    if (!ctx.pgid)
        ctx.pgid = pid;

    int saved_stdin = dup(STDIN_FILENO);
    dup2(pipefd[0], STDIN_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);

    int rc = run_command(node->right, ctx);
    if (rc < 0) {
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
        return rc;
    }

    dup2(saved_stdin, STDIN_FILENO);
    close(saved_stdin);

    return waitpid(pid, NULL, 0);
}

static int run_redirect(const struct redirect_node* node,
                        struct run_context ctx) {
    int flags = node->is_write ? (O_WRONLY | O_CREAT) : O_RDONLY;
    int redirected_fd = node->fd;
    if (redirected_fd < 0)
        redirected_fd = node->is_write ? STDOUT_FILENO : STDIN_FILENO;

    int fd = open(node->pathname, flags, 0);
    if (fd < 0) {
        perror("open");
        return RUN_ERROR;
    }
    int saved_fd = dup(redirected_fd);
    dup2(fd, redirected_fd);
    close(fd);

    int rc = run_command(node->inner, ctx);
    dup2(saved_fd, redirected_fd);
    close(saved_fd);
    return rc;
}

static int run_background(const struct background_node* node,
                          struct run_context ctx) {
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return RUN_ERROR;
    }
    if (pid == 0) {
        ctx.pgid = getpid();
        ctx.foreground = false;
        if (run_command(node->inner, ctx) == RUN_ERROR)
            abort();
        exit(EXIT_SUCCESS);
    }
    return 0;
}

static int run_command(const struct node* node, struct run_context ctx) {
    switch (node->type) {
    case CMD_EXECUTE:
        return run_execute(&node->execute, ctx);
    case CMD_JUXTAPOSITION:
        return run_juxtaposition(&node->juxtaposition, ctx);
    case CMD_PIPE:
        return run_pipe(&node->pipe, ctx);
    case CMD_REDIRECT:
        return run_redirect(&node->redirect, ctx);
    case CMD_BACKGROUND:
        return run_background(&node->background, ctx);
    }
    UNREACHABLE();
}

static struct parser parser;

enum {
    RESULT_SUCCESS,
    RESULT_FATAL_ERROR,
    RESULT_RECOVERABLE_ERROR,
};

static int parse_and_run(char* line) {
    struct node* node = parse(&parser, line);
    switch (parser.result) {
    case PARSE_SUCCESS:
        ASSERT(node);
        break;
    case PARSE_EMPTY:
        return RESULT_SUCCESS;
    case PARSE_NOMEM_ERROR:
        dprintf(STDERR_FILENO, "Out of memory\n");
        return RESULT_FATAL_ERROR;
    case PARSE_SYNTAX_ERROR:
        dprintf(STDERR_FILENO, "Syntax error\n");
        return RESULT_RECOVERABLE_ERROR;
    case PARSE_TOO_MANY_ARGS_ERROR:
        dprintf(STDERR_FILENO, "Too many arguments\n");
        return RESULT_RECOVERABLE_ERROR;
    default:
        UNREACHABLE();
    }

    // reap previous background processes
    while (waitpid(-1, NULL, WNOHANG) >= 0)
        ;

    struct run_context ctx = {.pgid = 0, .foreground = true};
    int run_result = run_command(node, ctx);
    destroy_node(node);
    if (run_result == RUN_ERROR)
        return RESULT_FATAL_ERROR;

    return RESULT_SUCCESS;
}

static int script_main(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return EXIT_FAILURE;
    }

    static char input[BUF_SIZE + 1];
    input[BUF_SIZE] = 0;

    int ret = EXIT_SUCCESS;
    ssize_t nread = -1;
    for (;;) {
        // Read unless we reached EOF in the previous iteration
        if (nread != 0) {
            for (size_t cursor = 0; cursor < BUF_SIZE;) {
                nread = read(fd, input + cursor, BUF_SIZE - cursor);
                if (nread < 0) {
                    perror("read");
                    return EXIT_FAILURE;
                }
                if (nread == 0)
                    break;
                cursor += nread;
            }
        }

        char* newline = strchr(input, '\n');
        if (newline)
            *newline = 0;

        switch (parse_and_run(input)) {
        case RESULT_SUCCESS:
            break;
        case RESULT_FATAL_ERROR:
            return EXIT_FAILURE;
        case RESULT_RECOVERABLE_ERROR:
            ret = EXIT_FAILURE;
            break;
        default:
            UNREACHABLE();
        }

        if (newline && newline + 1 < input + BUF_SIZE) {
            // Move the unprompted part to the beginning of the buffer
            memmove(input, newline + 1, BUF_SIZE - (newline - input) - 1);
        } else if (nread == 0) {
            // We have processed the whole buffer and reached EOF
            return ret;
        } else {
            // We have processed the whole buffer but haven't reached EOF
            memset(input, 0, sizeof(input));
        }
    }
}

static int repl_main(void) {
    size_t terminal_width = 80;
    struct winsize winsize;
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &winsize) >= 0)
        terminal_width = winsize.ws_col;

    static struct line_editor editor;
    if (tcgetattr(STDIN_FILENO, &editor.default_termios) < 0) {
        perror("tcgetattr");
        return EXIT_FAILURE;
    }

    for (;;) {
        char* input = read_input(&editor, terminal_width);
        if (!input)
            return EXIT_FAILURE;
        dprintf(STDERR_FILENO, "\n");

        switch (parse_and_run(input)) {
        case RESULT_SUCCESS:
            break;
        case RESULT_FATAL_ERROR:
            return EXIT_FAILURE;
        case RESULT_RECOVERABLE_ERROR:
            continue;
        default:
            UNREACHABLE();
        }

        // print 1 line worth of spaces so that we always ends up on a new line
        size_t num_spaces = terminal_width - 1;
        char* spaces = malloc(num_spaces + 1);
        if (!spaces) {
            perror("malloc");
            return EXIT_FAILURE;
        }
        memset(spaces, ' ', num_spaces);
        spaces[num_spaces] = 0;
        dprintf(STDERR_FILENO,
                "\x1b[?25l"            // hide cursor
                "\x1b[90;107m%%\x1b[m" // show end of line mark
                "%s"
                "\x1b[G"     // go to left end
                "\x1b[?25h", // show cursor
                spaces);
        free(spaces);
    }
}

int main(int argc, char* const argv[]) {
    if (tcsetpgrp(STDIN_FILENO, getpid()) < 0) {
        perror("tcsetpgrp");
        return EXIT_FAILURE;
    }

    if (argc >= 2)
        return script_main(argv[1]);
    return repl_main();
}
