import { defineConfig } from 'vite-plus';

export default defineConfig({
  fmt: {
    semi: true,
    singleQuote: true,
  },
  lint: {
    ignorePatterns: ['dist/**', 'native/**'],
    options: {
      typeAware: true,
      typeCheck: true,
    },
  },
  test: {
    include: ['test/**/*.test.ts'],
  },
  pack: {
    entry: ['src/cli.ts'],
    clean: true,
    format: ['esm'],
    minify: false,
    outExtensions: () => ({ js: '.js' }),
    sourcemap: false,
  },
});
