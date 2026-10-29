export type FilesData = { [filename: string]: Uint8Array };

export interface ExtractedFileChunk {
  path: string;
  size: number;
  offset: number;
  data: Uint8Array;
  final: boolean;
}

export interface IUnpackJSAPI {
  extractData: (data: Uint8Array, decompressionOnly?: boolean) => Promise<FilesData>;
  extract: (url: string) => Promise<FilesData>;
  extractDataStream: (
    data: Uint8Array,
    decompressionOnly?: boolean
  ) => AsyncGenerator<ExtractedFileChunk>;
  extractStream: (url: string) => AsyncGenerator<ExtractedFileChunk>;
}
