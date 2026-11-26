/**
 * 统一 API 封装 — 异步任务 + 轮询模式
 * - POST /api/scan  → 立即返回 task_id（不再等待扫描完成）
 * - GET  /api/tasks/{id} → 轮询任务状态 / 进度 / 结果
 * - timeout 15s（POST 立即返回，不需要长超时；轮询自己控制）
 */
import axios from 'axios'
import { ElMessage } from 'element-plus'

const api = axios.create({
  baseURL: '',
  timeout: 15000,            // 15s 足够（POST /api/scan 立即返回 task_id）
  headers: { 'Content-Type': 'application/json' },
})

// 响应拦截器：统一错误处理
api.interceptors.response.use(
  (res) => res.data,
  (err) => {
    const status = err.response?.status
    const body = err.response?.data
    let msg = err.message || '请求失败'

    if (body && body.message) {
      msg = body.message
    } else if (status === 422) {
      msg = '请求参数校验失败'
    } else if (status === 404) {
      msg = '接口不存在'
    } else if (status === 'ECONNABORTED') {
      msg = '网络超时，请检查网络连接后重试'
    }

    // 轮询接口的 404 不弹错（可能是任务过期），由上层处理
    const url = err.config?.url || ''
    if (url.startsWith('/api/tasks/')) {
      return Promise.reject(err)
    }

    ElMessage.error(`[${status || '网络'}] ${msg}`)
    return Promise.reject(err)
  },
)

// ========== 业务接口 ==========

/** POST /api/scan — 启动异步扫描任务，立即返回 task_id + 初始状态 */
export function startScanTask(repoUrl) {
  return api.post('/api/scan', { repo_url: repoUrl })
}

/** GET /api/tasks/{taskId} — 轮询任务状态 / 进度 / 结果 */
export function getTaskStatus(taskId) {
  return api.get(`/api/tasks/${taskId}`)
}

/** GET /health — 健康检查 */
export function health() {
  return api.get('/health')
}

export default api
