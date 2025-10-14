#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <archive.h>
#include <archive_entry.h>
#include <emscripten.h>

typedef struct {
    char* filename;
    uint8_t* data;
    size_t data_size;
} FileData;

typedef struct {
    FileData* files;
    size_t fileCount;
    int status;
    char error_message[256];
} ExtractedArchive;

ExtractedArchive* error_handler(ExtractedArchive* result, const char *error_message, struct archive* archive) {

    if (!result || !archive) {
        fprintf(stderr, "Archive is null\n");
        return NULL;
    }

    result->status = 0;

    snprintf(result->error_message, sizeof(result->error_message), "%s", error_message);
    archive_read_free(archive);
    return result;
}

EMSCRIPTEN_KEEPALIVE
ExtractedArchive* extract_archive(uint8_t* inputData, size_t inputSize ) {
    struct archive* archive;
    struct archive_entry* entry;
    size_t files_struct_length = 100;
    FileData* files = NULL;
    size_t files_count = 0;
    const char *error_message;
    bool hasSymLinks = false;

    ExtractedArchive* result = (ExtractedArchive*)malloc(sizeof(ExtractedArchive));
    if (!result) {
        return NULL;
    }

    result->files = NULL;
    result->fileCount = 0;
    result->status = 1;
    result->error_message[0] = '\0';

    archive = archive_read_new();
    archive_read_support_filter_all(archive);
    archive_read_support_format_all(archive);

    if (archive_read_open_memory(archive, inputData, inputSize) != ARCHIVE_OK) {
        return error_handler(result,archive_error_string(archive), archive);
    }
    files = malloc(sizeof(FileData) * files_struct_length);

    while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        const char* filename = archive_entry_pathname(entry);
        size_t entrySize = archive_entry_size(entry);

        // Ignore symbolic links for now
        if (archive_entry_filetype(entry) == AE_IFLNK) {
            hasSymLinks = true;
            continue;
        }

        if (files_count + 1 > files_struct_length) {
            files_struct_length *= 2; // double the length
            FileData* oldfiles = files;
            files= realloc(files, sizeof(FileData) * files_struct_length);
            if (!files) {
                result->fileCount = files_count;
                result->files = oldfiles; // otherwise memory is lost, alternatively also everything can be freed.
                error_message = "Memory allocation error for file data.";
                return error_handler(result, error_message, archive);
            }
        }

        files[files_count].filename = strdup(filename);
        files[files_count].data = malloc(entrySize);
        files[files_count].data_size = entrySize;

        if (!files[files_count].data) {
            free(files[files_count].filename);
            files[files_count].filename = NULL;
            result->fileCount = files_count;
            result->files = files; // otherwise memory is lost, alternatively also everything can be freed.
            error_message = "Memory allocation error for file contents.";
            return error_handler(result, error_message, archive);
        }

        size_t bytesRead = 0;
        while (bytesRead < entrySize) {
            ssize_t ret = archive_read_data(archive, files[files_count].data + bytesRead, entrySize - bytesRead);
            if (ret < 0) {
                for (size_t i = 0; i <= files_count; i++) {
                    free(files[i].filename);
                    free(files[i].data);
                }
                free(files);
                result->files = NULL;
                return error_handler(result, archive_error_string(archive), archive);
            }
            bytesRead += ret;
        }
        files_count++;
    }

    // Resolve symlinks
    if (hasSymLinks) {
        // Rewind and reopen the archive to iterate over symlinks
        archive_read_free(archive);
        archive = archive_read_new();
        archive_read_support_filter_all(archive);
        archive_read_support_format_all(archive);

        if (archive_read_open_memory(archive, inputData, inputSize) != ARCHIVE_OK) {
            return error_handler(result, archive_error_string(archive), archive);
        }

        struct archive_entry *symlink_entry;
        while (archive_read_next_header(archive, &symlink_entry) == ARCHIVE_OK) {
            // Process only symlinks this time
            if (archive_entry_filetype(symlink_entry) != AE_IFLNK) {
                continue;
            }

            const char *linkname = archive_entry_pathname(symlink_entry);
            const char *target = archive_entry_symlink(symlink_entry);

            // Target not found
            if (!target) {
                continue;
            }

            // Find the target file in the already populated files[]
            size_t target_index = (size_t)-1;
            for (size_t i = 0; i < files_count; i++) {
                if (strcmp(files[i].filename, target) == 0) {
                    target_index = i;
                    break;
                }
            }

            // Target not found in the processed files
            if (target_index == (size_t)-1 || !files[target_index].data) {
                continue;
            }

            // Add the symlink entry
            if (files_count + 1 > files_struct_length) {
                files_struct_length *= 2;
                FileData *oldfiles = files;
                files = realloc(files, sizeof(FileData) * files_struct_length);
                if (!files) {
                    result->fileCount = files_count;
                    result->files = oldfiles;
                    error_message = "Memory allocation error for symlink data.";
                    return error_handler(result, error_message, archive);
                }
            }

            files[files_count].filename = strdup(linkname);
            files[files_count].data_size = files[target_index].data_size;
            files[files_count].data = malloc(files[target_index].data_size);
            if (!files[files_count].data) {
                free(files[files_count].filename);
                files[files_count].filename = NULL;
                result->fileCount = files_count;
                result->files = files;
                error_message = "Memory allocation error for symlink target data.";
                return error_handler(result, error_message, archive);
            }
            memcpy(files[files_count].data, files[target_index].data, files[target_index].data_size);

            files_count++;
        }
    }

    archive_read_free(archive);
    result->files = files;
    result->fileCount = files_count;
    result->status = 1;
    return result;
}

char* write_to_temp_file(uint8_t* data, size_t size) {
    char* temp_file_name = strdup("/tmp/decompressionXXXXXX");
    int fd = mkstemp(temp_file_name);
    if (fd == -1) {
        perror("Failed to create temporary file for decompression file");
        free(temp_file_name);
        return NULL;
    }

    FILE* temp_file = fdopen(fd, "wb");
    if (!temp_file) {
        perror("Failed to open temporary file");
        close(fd);
        unlink(temp_file_name);
        free(temp_file_name);
        return NULL;
    }

    if (fwrite(data, 1, size, temp_file) != size) {
        perror("Failed to write to temporary file");
        fclose(temp_file);
        unlink(temp_file_name);
        free(temp_file_name);
        return NULL;
    }

    fclose(temp_file);
    return temp_file_name;
}

EMSCRIPTEN_KEEPALIVE
ExtractedArchive* decompression(uint8_t* inputData, size_t inputSize) {
    struct archive* archive;
    struct archive_entry* entry;
    size_t files_count = 0;

    const size_t buffsize = 64 * 1024;
    char buff[buffsize];
    size_t total_size = 0;
    const char *error_message;

    FileData* files = malloc(sizeof(FileData) * (files_count + 1));

    if (!files) {
        printf("Failed to allocate memory for files array\n");
        return NULL;
    }

    ExtractedArchive* result = (ExtractedArchive*)malloc(sizeof(ExtractedArchive));
    if (!result) {
        free(files);
        return NULL;
    }

    result->files = NULL;
    result->fileCount = 0;
    result->status = 1;
    result->error_message[0] = '\0';

    char* temp_file_name = write_to_temp_file(inputData, inputSize);
    if (!temp_file_name) {
        free(files);
        error_message = "Failed to create temporary file";
        return error_handler(result, error_message, archive);
    }

    archive = archive_read_new();
    archive_read_support_filter_all(archive);
    archive_read_support_format_raw(archive);

    if (archive_read_open_filename(archive, temp_file_name, inputSize) != ARCHIVE_OK) {
        unlink(temp_file_name);
        free(temp_file_name);
        free(files);
        return error_handler(result, archive_error_string(archive), archive);
    }

    while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        const char* filename = archive_entry_pathname(entry);
        if (!filename) filename = "decompression";

        files[files_count].filename = strdup(filename);
        files[files_count].data = NULL;
        files[files_count].data_size = 0;

        ssize_t ret;

        for (;;) {
            ret = archive_read_data(archive, buff, buffsize);
            if (ret < 0) {
                for (size_t i = 0; i <= files_count; i++) {
                        free(files[i].filename);
                        free(files[i].data);
                    }
                    free(files);
                    result->files = NULL;
                    return error_handler(result, archive_error_string(archive), archive);
            }
            if (ret == 0) {
                break;
            }

            void* new_data = realloc(files[files_count].data, total_size + ret);
            if (!new_data) {
                free(files[files_count].data);
                error_message = "Memory allocation error";
                return error_handler(result, error_message, archive);
            }

            files[files_count].data = new_data;
            memcpy(files[files_count].data + total_size, buff, ret);
            total_size += ret;
        }
        files[files_count].data_size = total_size;
        files_count++;
    }

    archive_read_free(archive);
    unlink(temp_file_name);
    free(temp_file_name);

    result->files = files;
    result->fileCount = files_count;
    result->status =  1;
    return result;
}

EMSCRIPTEN_KEEPALIVE
ExtractedArchive* extract(uint8_t* inputData, size_t inputSize, bool decompressionOnly ) {
    if (!decompressionOnly) {
        return extract_archive(inputData, inputSize);
    } else {
        return decompression(inputData, inputSize);
    }
}

EMSCRIPTEN_KEEPALIVE
void free_extracted_archive(ExtractedArchive* archive) {
    if (!archive) {
            fprintf(stderr, "No archive\n");
    }
    for (size_t i = 0; i < archive->fileCount; i++) {
        free(archive->files[i].filename);
        free(archive->files[i].data);
    }
    free(archive->files);
    free(archive);
}
