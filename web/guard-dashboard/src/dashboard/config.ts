const env = import.meta.env;

export const API = env.VITE_KONTEXT_API ?? "";
export const USE_SAMPLE_DATA = env.DEV && env.VITE_KONTEXT_SAMPLE_DATA === "1";
