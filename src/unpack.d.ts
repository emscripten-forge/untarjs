export interface IWasmModule {
  wasmMemory: any;
  _free_extracted_archive(resultPtr: number): void;
  UTF8ToString(filenamePtr: number): string;
  HEAPU8: Uint8Array;
  _malloc(size: number): number;
  _free(ptr: number): void;
  _extract_archive(
    inputPtr: number,
    inputSize: number,
    fileCountPtr: number
  ): number;
  getValue(ptr: number, type: string): number;
}

declare const unpack: {
  (options: { locateFile: (path: string) => string }): Promise<IWasmModule>;
};

export default unpack;
