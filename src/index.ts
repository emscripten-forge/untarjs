import initializeWasm from './helper';
import { ExtractedFileChunk, FilesData, IUnpackJSAPI } from './types';

const STREAM_CHUNK_SIZE = 256 * 1024;

export const fetchByteArray = async (url: string): Promise<Uint8Array> => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
};

export const initUntarJS = async (locateWasm?: (file: string) => string): Promise<IUnpackJSAPI> => {
  const wasmModule = await initializeWasm(locateWasm);

  const extractData = async (
    data: Uint8Array,
    decompressionOnly: boolean = false
  ): Promise<FilesData> => {
    /**Since WebAssembly, memory is accessed using pointers
      and the first parameter of extract method from unpack.c, which is Uint8Array of file data, should be a pointer
      so we have to allocate memory for file data
    **/
    let inputPtr: number | null = wasmModule._malloc(data.length);
    new Uint8Array(wasmModule.wasmMemory.buffer).set(data, inputPtr);


    let resultPtr: number | null = wasmModule._extract(
      inputPtr,
      data.length,
      decompressionOnly
    );
    const files: FilesData = {};
    /**
     * Since extract returns a pointer that refers to an instance of the ExtractedArchive in unpack.c
        typedef struct {
          FileData* files;
          size_t fileCount;
          int status;
          char* error_message;
        } ExtractedArchive;

      its fields are laid out in memory sequentially. Based on this and types each field will take 4 bytes:

          4 bytes        4 bytes         4 bytes         4 bytes
      ---------------|---------------|---------------|---------------
    files            fileCount         status        error_message

      `resultPtr` points to the beginning of the ExtractedArchive structure in WebAssembly memory
      and in order to get pointer of statusPtr we need to calculate it as: 0(offset of file pointer) + 4 (offset of fileCount) + 4 (offset for status)
      'status' field and pointer of `error_message` are 32-bit signed integer
    */
    let statusPtr: number | null = wasmModule.getValue(resultPtr + 8, 'i32');
    let errorMessagePtr: number | null = resultPtr + 12;
    if (statusPtr !== 1) {
      const errorMessage = wasmModule.UTF8ToString(errorMessagePtr);
      console.error(
        'Extraction failed with status:',
        statusPtr,
        'Error:',
        errorMessage
      );
      wasmModule._free(inputPtr);
      wasmModule._free_extracted_archive(resultPtr);
      inputPtr = null;
      resultPtr = null;
      errorMessagePtr = null;
      throw new Error(errorMessage);
    }
    const filesPtr = wasmModule.getValue(resultPtr, 'i32');
    const fileCount = wasmModule.getValue(resultPtr + 4, 'i32');
    const wasmHeap = new Uint8Array(wasmModule.wasmMemory.buffer);

    /**
     * FilesPtr is a pointer that refers to an instance of the FileData in unpack.c
        typedef struct {
          char* filename;
          uint8_t* data;
          size_t data_size;
        } FileData;

      and its fields are laid out in memory sequentially too so each field take 4 bytes:

          4 bytes        4 bytes         4 bytes
      ---------------|---------------|---------------
    filename            data         data_size

    `filesPtr + i * 12` calculates the memory address of the i-th FileData element in the array
      where `12` is the size of each FileData structure in memory in bytes: 4 + 4 + 4
    */

    for (let i = 0; i < fileCount; i++) {
      const fileDataPtr = filesPtr + i * 12;
      const filenamePtr = wasmModule.getValue(fileDataPtr, 'i32');
      const dataSize = wasmModule.getValue(fileDataPtr + 8, 'i32');
      const dataPtr = wasmModule.getValue(fileDataPtr + 4, 'i32');
      const filename = wasmModule.UTF8ToString(filenamePtr);
      files[filename] = wasmHeap.slice(dataPtr, dataPtr + dataSize);
    }

    wasmModule._free(inputPtr);
    wasmModule._free_extracted_archive(resultPtr);
    inputPtr = null;
    resultPtr = null;
    errorMessagePtr = null;

    return files;
  };

  const extract = async (url: string): Promise<FilesData> => {
    let isArchive: boolean = checkIsArchive(url);
    const data = await fetchByteArray(url);
    return extractData(data, !isArchive);
  };

  const extractDataStream = (
    data: Uint8Array,
    decompressionOnly: boolean = false
  ): AsyncGenerator<ExtractedFileChunk> => {
    let inputData: Uint8Array | undefined = data;

    return (async function* () {
      const inputSize = inputData?.length ?? 0;
      const inputPtr = wasmModule._malloc(inputSize);
      let streamPtr = 0;
      let chunkPtr = 0;

      try {
        if (inputSize > 0 && !inputPtr) {
          throw new Error('Failed to allocate archive input');
        }
        if (!inputData) {
          throw new Error('Archive data is unavailable');
        }
        new Uint8Array(wasmModule.wasmMemory.buffer).set(inputData, inputPtr);
        inputData = undefined;
        streamPtr = wasmModule._archive_stream_open(
          inputPtr,
          inputSize,
          decompressionOnly
        );
        if (!streamPtr) {
          throw new Error('Failed to allocate archive stream');
        }
        chunkPtr = wasmModule._malloc(STREAM_CHUNK_SIZE);
        if (!chunkPtr) {
          throw new Error('Failed to allocate archive stream buffer');
        }

        const getStreamError = () =>
          wasmModule.UTF8ToString(wasmModule._archive_stream_error(streamPtr));

        let entryStatus = wasmModule._archive_stream_next_entry(streamPtr);
        while (entryStatus === 1) {
          const path = wasmModule.UTF8ToString(
            wasmModule._archive_stream_entry_path(streamPtr)
          );
          const size = wasmModule._archive_stream_entry_size(streamPtr);
          let offset = 0;
          let bytesRead = wasmModule._archive_stream_read(
            streamPtr,
            chunkPtr,
            STREAM_CHUNK_SIZE
          );

          if (bytesRead < 0) {
            throw new Error(getStreamError());
          }
          if (bytesRead === 0) {
            yield { path, size, offset, data: new Uint8Array(0), final: true };
          }

          while (bytesRead > 0) {
            const chunk = new Uint8Array(
              wasmModule.wasmMemory.buffer,
              chunkPtr,
              bytesRead
            ).slice();
            const nextBytesRead = wasmModule._archive_stream_read(
              streamPtr,
              chunkPtr,
              STREAM_CHUNK_SIZE
            );

            if (nextBytesRead < 0) {
              yield { path, size, offset, data: chunk, final: false };
              throw new Error(getStreamError());
            }

            yield {
              path,
              size,
              offset,
              data: chunk,
              final: nextBytesRead === 0
            };
            offset += bytesRead;
            bytesRead = nextBytesRead;
          }

          entryStatus = wasmModule._archive_stream_next_entry(streamPtr);
        }

        if (entryStatus < 0) {
          throw new Error(getStreamError());
        }
      } finally {
        if (streamPtr) {
          wasmModule._archive_stream_close(streamPtr);
        }
        if (chunkPtr) {
          wasmModule._free(chunkPtr);
        }
        wasmModule._free(inputPtr);
      }
    })();
  };

  const extractStream = async function* (
    url: string
  ): AsyncGenerator<ExtractedFileChunk> {
    let data: Uint8Array | undefined = await fetchByteArray(url);
    const stream = extractDataStream(data, !checkIsArchive(url));
    data = undefined;
    yield* stream;
  };

  const checkIsArchive = (url: string): boolean => {
    let isArchive: boolean = false;
    let archiveExtArr = ['.conda', 'tar.bz2', 'tar.gz', '.zip'];
    archiveExtArr.forEach(type => {
      if (url.toLowerCase().endsWith(type)) {
        isArchive = true;
      }
    });
    return isArchive;
  };

  return {
    extract,
    extractData,
    extractDataStream,
    extractStream
  };
};

export * from './types';
