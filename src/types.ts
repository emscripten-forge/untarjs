export type FilesData = { [filename: string]: Uint8Array };

export interface IUnpackJSAPI {
  extractData: (data: Uint8Array) => FilesData;
  extract: (url: string) => Promise<FilesData>;
}
