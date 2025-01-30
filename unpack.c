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
ExtractedArchive* extract_archive(uint8_t* input_data, size_t input_size ) {
    struct archive* archive;
    struct archive_entry* entry;
    size_t files_struct_length = 100;
    FileData* files = NULL;
    size_t files_count = 0;
    const char *error_message;

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

    if (archive_read_open_memory(archive, input_data, input_size) != ARCHIVE_OK) {
        return error_handler(result,archive_error_string(archive), archive); 
    }
    files = malloc(sizeof(FileData) * files_struct_length);

    while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        const char* filename = archive_entry_pathname(entry);
        size_t entrySize = archive_entry_size(entry);
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
    if (fclose(temp_file) != 0) {
        perror("Failed to close temporary file");
        unlink(temp_file_name);
        free(temp_file_name);
        return NULL;
    }

    return temp_file_name;
}

EMSCRIPTEN_KEEPALIVE
ExtractedArchive* decompression(uint8_t* input_data, size_t input_size) {
    struct archive* archive;
    struct archive_entry* entry;
    size_t files_count = 0;
    size_t total_size = 0;
    const char *error_message;
    size_t files_struct_length = 1;
    size_t compression_ratio = 10;
    size_t estimated_decompressed_size = input_size * compression_ratio;
    const size_t buffsize = estimated_decompressed_size;
    char* buff = (char*)malloc(buffsize);

    if (!buff) {
        printf("Failed to allocate memory for decompression buffer\n");
        return NULL;
    }

    FileData* files = malloc(sizeof(FileData) * files_struct_length);
    if (!files) {
        printf("Failed to allocate memory for files array\n");
        free(buff);
        return NULL;
    }

    ExtractedArchive* result = (ExtractedArchive*)malloc(sizeof(ExtractedArchive));
    if (!result) {
        free(files);
        free(buff);
        return NULL;
    }

    result->files = NULL;
    result->fileCount = 0;
    result->status = 1;
    result->error_message[0] = '\0';

    char* temp_file_name = write_to_temp_file(input_data, input_size);
    if (!temp_file_name) {
        free(files);
        free(buff);
        error_message = "Failed to create temporary file";
        return error_handler(result, error_message, archive);
    }

    archive = archive_read_new();
    archive_read_support_filter_all(archive);
    archive_read_support_format_raw(archive);
   
    if (archive_read_open_filename(archive, temp_file_name, buffsize) != ARCHIVE_OK) {
        unlink(temp_file_name);
        free(temp_file_name);
        free(files);
        free(buff);
        return error_handler(result, archive_error_string(archive), archive);
    }
  
    while (archive_read_next_header(archive, &entry) == ARCHIVE_OK) {
        if (files_count + 1 > files_struct_length) {
            files_struct_length *= 2; // double the length
            FileData* oldfiles = files;
            files= realloc(files, sizeof(FileData) * files_struct_length);
            if (!files) {
                unlink(temp_file_name);
                free(temp_file_name);
                result->fileCount = files_count;
                result->files = oldfiles;
                error_message = "Memory allocation error for file data.";
                return error_handler(result, error_message, archive);
            }     
        }

        const char* filename = archive_entry_pathname(entry);
        if (!filename) filename = "data";

        files[files_count].filename = strdup(filename);
        files[files_count].data = malloc(estimated_decompressed_size);

         if (!files[files_count].data) {
            free(files[files_count].filename);
             unlink(temp_file_name);
            free(temp_file_name);
            free(buff);
            files[files_count].filename = NULL;
            result->fileCount = files_count;
            result->files = files;

            error_message = "Memory allocation error for file contents.";
            return error_handler(result, error_message, archive);
        }
        files[files_count].data_size = buffsize;

        ssize_t ret;
        total_size = 0; 

        while (1) {
            ret = archive_read_data(archive, buff, buffsize);

            if (ret < 0) {
                for (size_t i = 0; i <= files_count; i++) {
                    free(files[i].filename);
                    free(files[i].data);
                }
                free(files);
                free(buff);
                unlink(temp_file_name);
                free(temp_file_name);
                result->files = NULL;
                result = error_handler(result, archive_error_string(archive), archive);
                break;
            }
            if (ret == 0) {
                break;
            }

            size_t sum = total_size + ret;
            if (sum > estimated_decompressed_size) {
                size_t new_size = estimated_decompressed_size * 1.5; 
                void* new_data = realloc(files[files_count].data, new_size);//?
                if (!new_data) {
                   for (size_t i = 0; i <= files_count; i++) {
                        free(files[i].filename);
                        free(files[i].data);
                    }
                    
                    result->files = NULL;
                    result->fileCount = 0;
                    free(files);
                    free(buff);
                    unlink(temp_file_name);
                    free(temp_file_name);
                    error_message = "Memory allocation error";
                    result = error_handler(result, error_message, archive);
                    break;
                }

                files[files_count].data = new_data;
                estimated_decompressed_size = new_size;

            } else if (sum>0 && sum < estimated_decompressed_size) {
                  memcpy(files[files_count].data + total_size, buff, ret);
                  total_size += ret;
                  break;
            }

            memcpy(files[files_count].data + total_size, buff, ret);
            total_size += ret;
        }
      

        files[files_count].data_size = total_size;
        files_count++;
        free(buff);
    }
    archive_read_free(archive);
    unlink(temp_file_name);
    free(temp_file_name);
    result->files = files;
    result->fileCount = files_count;
    result->status = 1;
    return result;
}

 
EMSCRIPTEN_KEEPALIVE
ExtractedArchive* extract(uint8_t* input_data, size_t input_size, bool decompression_only ) {
    if (!decompression_only) {
        return extract_archive(input_data, input_size);
    } else {
        return decompression(input_data, input_size);
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