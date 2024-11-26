import initializeWasm from './helper';
import { FilesData, IUnpackJSAPI } from './types';

const fetchByteArray = async (url: string): Promise<Uint8Array> => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
};

export const initUntarJS = async (): Promise<IUnpackJSAPI> => {
  const wasmModule = await initializeWasm();

  const extractData = (data: Uint8Array): FilesData => {
    /**Since WebAssembly, memory is accessed using pointers
      and the first parameter of extract_archive method from unpack.c, which is Uint8Array of file data, should be a pointer
      so we have to allocate memory for file data
    **/
    let inputPtr: number | null = wasmModule._malloc(data.length);
    wasmModule.HEAPU8.set(data, inputPtr);

    // fileCountPtr is the pointer to 4 bytes of memory in WebAssembly's heap that holds fileCount value from the ExtractedArchive structure in unpack.c.
    let fileCountPtr: number | null = wasmModule._malloc(4);

    let resultPtr: number | null = wasmModule._extract_archive(
      inputPtr,
      data.length,
      fileCountPtr
    );

    /**
     * Since extract_archive returns a pointer that refers to an instance of the ExtractedArchive in unpack.c
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
    let errorMessagePtr: number | null = wasmModule.getValue(
      resultPtr + 12,
      'i32'
    );
    if (statusPtr !== 1) {
      const errorMessage = wasmModule.UTF8ToString(errorMessagePtr);
      console.error(
        'Extraction failed with status:',
        statusPtr,
        'Error:',
        errorMessage
      );
      wasmModule._free(inputPtr);
      wasmModule._free(fileCountPtr);
      wasmModule._free(errorMessagePtr);
      wasmModule._free_extracted_archive(resultPtr);
      return {};
    }
    const filesPtr = wasmModule.getValue(resultPtr, 'i32');
    const fileCount = wasmModule.getValue(resultPtr + 4, 'i32');

    const files: FilesData = {};

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
      const fileData = new Uint8Array(
        wasmModule.HEAPU8.buffer,
        dataPtr,
        dataSize
      );

      const fileDataCopy = new Uint8Array(Array.from(fileData));

      files[filename] = fileDataCopy;
    }
    let newFiles = { ...files };
    wasmModule._free(inputPtr);
    wasmModule._free(fileCountPtr);
    wasmModule._free(errorMessagePtr);
    wasmModule._free_extracted_archive(resultPtr);
    inputPtr = null;
    fileCountPtr = null;
    resultPtr = null;
    errorMessagePtr = null;

    return newFiles;
  };

  const extract = async (url: string): Promise<FilesData> => {
    const data = await fetchByteArray(url);
    return extractData(data);
  };

  return {
    extract,
    extractData
  };
};

export * from './types';
