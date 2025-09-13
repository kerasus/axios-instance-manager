import { defineConfig } from 'vite'
import dts from 'vite-plugin-dts'
import path from 'path'

export default defineConfig({
    build: {
        lib: {
            entry: path.resolve(__dirname, 'src/index.ts'),
            name: 'AxiosInstanceManager',
            formats: ['es', 'cjs'],
            fileName: (format) => `index.${format}.js`,
        },
        rollupOptions: {
            external: ['vue', 'axios', 'vue-router'],
            output: {
                globals: {
                    vue: 'Vue',
                    axios: 'axios',
                    'vue-router': 'VueRouter',
                },
                exports: 'named'
            },
        },
        sourcemap: true,
    },
    plugins: [
        dts({
            insertTypesEntry: true,
            rollupTypes: true,
        }),
    ],
    esbuild: {
        target: 'esnext',
    },
})
