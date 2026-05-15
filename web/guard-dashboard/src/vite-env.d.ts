/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_KONTEXT_API?: string;
  readonly VITE_KONTEXT_SAMPLE_DATA?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
