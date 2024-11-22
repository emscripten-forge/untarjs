import { IWasmModule } from "./unpack";

export type FilesData = {[filename: string]: Uint8Array};

export interface IUnpackJSAPI {
  extractData: (data: Uint8Array) => Promise<FilesData>;
  extract: (url: string) => Promise<FilesData>;
  wasmModule: IWasmModule 
}
