#include <stdio.h>
#include <string.h>
#include <stdlib.h>
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

EMSCRIPTEN_KEEPALIVE
ExtractedArchive* extract_archive(uint8_t* inputData, size_t inputSize, size_t* fileCount) {
    struct archive* archive;
    struct archive_entry* entry;
    FileData* files = NULL;
    size_t files_count = 0;

    ExtractedArchive* result = (ExtractedArchive*)malloc(sizeof(ExtractedArchive));
    if (!result) {
        result->status = 0;
        snprintf(result->error_message, sizeof(result->error_message), "Memory allocation error for ExtractedArchive.");
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
        archive_read_free(archive);
        result->status = 0;
        snprintf(result->error_message, sizeof(result->error_message), "%s", archive_error_string(archive));
        return result;
    }

    while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        const char* filename = archive_entry_pathname(entry);
        size_t entrySize = archive_entry_size(entry);

        files = realloc(files, sizeof(FileData) * (files_count + 1));
  
        if (!files) {
            archive_read_free(archive);
            result->status = 0;
            snprintf(result->error_message, sizeof(result->error_message), "Memory allocation error for FileData array.");
            return result;
        }
        char* filename_tmp = strdup(filename);
        files[files_count].filename = filename_tmp;
        files[files_count].data = malloc(entrySize);
        files[files_count].data_size = entrySize;

        if (!files[files_count].data) {
            free(files[files_count].filename);
            archive_read_free(archive);
            result->status = 0;
            snprintf(result->error_message, sizeof(result->error_message), "Memory allocation error for file data.");
            return result;
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
                archive_read_free(archive);
                result->status = 0;
                 snprintf(result->error_message, sizeof(result->error_message),  "%s", archive_error_string(archive));
                return result;
            }
            bytesRead += ret;
        }
        files_count++;
    }

    archive_read_free(archive);
    result->files = files;
    result->fileCount = files_count;
    result->status = 1;
    return result;
}


EMSCRIPTEN_KEEPALIVE
void free_extracted_archive(ExtractedArchive* archive) {
    if (!archive) return;

    for (size_t i = 0; i < archive->fileCount; i++) {
        free(archive->files[i].filename);
        free(archive->files[i].data);
    }

    free(archive->files);
    free(archive);
}
