const { defineConfig } = require('@vue/cli-service')

module.exports = defineConfig({
  transpileDependencies: true,
  devServer: {
    port: 5175,
    // 开发代理：把 /api 和 /health 转发到后端 FastAPI
    // target 用 127.0.0.1 而非 localhost，确保和后端 --host 127.0.0.1 对齐
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8001',
        changeOrigin: true,
        logLevel: 'debug',
      },
      '/health': {
        target: 'http://127.0.0.1:8001',
        changeOrigin: true,
        logLevel: 'debug',
      },
    },
  },
})
