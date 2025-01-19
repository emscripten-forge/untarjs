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

  const extractData = async (
    data: Uint8Array,
    decompressionOnly: boolean = false
  ): Promise<FilesData> => {
    /**Since WebAssembly, memory is accessed using pointers
      and the first parameter of extract_archive method from unpack.c, which is Uint8Array of file data, should be a pointer
      so we have to allocate memory for file data
    **/
    let inputPtr: number | null = wasmModule._malloc(data.length);
    wasmModule.HEAPU8.set(data, inputPtr);


    let resultPtr: number | null = wasmModule._extract_archive(
      inputPtr,
      data.length,
      decompressionOnly
    );
    const files: FilesData = {};
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

      const fileDataCopy = fileData.slice(0);
      files[filename] = fileDataCopy;
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

  const checkIsArchive = (url: string): boolean => {
    let isArchive: boolean = false;
    let archiveExtArr = ['.conda', 'tar.bz2', 'tar.gz'];
    archiveExtArr.forEach(type => {
      if (url.toLowerCase().endsWith(type)) {
        isArchive = true;
      }
    });
    return isArchive;
  };

  return {
    extract,
    extractData
  };
};

export * from './types';
