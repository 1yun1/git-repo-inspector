<template>
  <div class="app">
    <!-- 顶部标题栏 -->
    <header class="header">
      <div class="header-inner">
        <h1>🔍 Git 仓库接入体检工具</h1>
        <p class="subtitle">输入公开 GitHub 仓库链接，自动检测完备度与风险</p>
      </div>
    </header>

    <main class="container">
      <!-- 输入区 -->
      <section class="card input-card">
        <el-form inline @submit.prevent>
          <el-form-item label="仓库链接">
            <el-input
              v-model="repoUrl"
              placeholder="当前版本支持公开 GitHub、Gitee 仓库链接"
              size="large"
              style="width: 480px"
              clearable
              @keyup.enter="doScan"
            />
          </el-form-item>
          <el-form-item>
            <el-button
              type="primary"
              size="large"
              :loading="loading"
              @click="doScan"
            >
              {{ loading ? '扫描中...' : '开始扫描' }}
            </el-button>
            <el-button
              size="large"
              plain
              :disabled="loading || !result"
              @click="reset"
            >
              清空
            </el-button>
          </el-form-item>
        </el-form>

        <!-- 扫描进度（loading 时显示） -->
        <div v-if="loading" class="progress-box">
          <el-progress
            :percentage="progress"
            :stroke-width="14"
            :color="progressBarColor"
            :text-inside="true"
            :show-text="true"
            :status="progress >= 95 ? 'success' : ''"
          />
          <div class="progress-text">
            {{ progressText || '正在扫描...' }}
          </div>
        </div>
      </section>

      <!-- 结果区 -->
      <section v-if="result" class="result">
        <!-- 顶栏：仓库信息 + 风险等级徽章 -->
        <div class="result-header">
          <div class="repo-title">
            <h2>
              <el-tag size="large" effect="dark" type="primary">{{ result.repo_info.owner }}</el-tag>
              <span class="repo-sep">/</span>
              <el-tag size="large" effect="dark" type="success">{{ result.repo_info.repo }}</el-tag>
            </h2>
            <div class="repo-meta">
              平台：<strong>{{ (result.repo_info.provider || 'github') === 'gitee' ? 'Gitee' : 'GitHub' }}</strong>
              &nbsp;|&nbsp;
              默认分支：<strong>{{ result.repo_info.default_branch }}</strong>
              &nbsp;|&nbsp;
              文件数：<strong>{{ result.repo_info.total_files }}</strong>
            </div>
          </div>
          <div class="risk-badge">
            <el-tag :type="riskTagType" effect="dark" size="large" round>
              风险等级：{{ result.summary.risk_level }}
            </el-tag>
          </div>
        </div>

        <el-row :gutter="20">
          <!-- 左列：评分 + 完备度 -->
          <el-col :span="12">
            <!-- 评分仪表盘 -->
            <div class="card">
              <h3>📊 接入就绪度评分</h3>
              <!-- 分数区间说明 -->
              <div class="score-legend">
                <span class="legend-label">分数区间：</span>
                <el-tag type="success" effect="plain" size="small">优秀 80–100</el-tag>
                <el-tag type="primary" effect="plain" size="small">合格 60–79</el-tag>
                <el-tag type="warning" effect="plain" size="small">需改进 40–59</el-tag>
                <el-tag type="danger" effect="plain" size="small">危险 0–39</el-tag>
              </div>
              <div ref="chartRef" class="chart"></div>
              <!-- 扣分明细 -->
              <div v-if="result.summary.score_detail.deductions.length" class="deductions">
                <h4>扣分明细</h4>
                <el-table :data="result.summary.score_detail.deductions" size="small" border>
                  <el-table-column prop="item" label="扣分原因" />
                  <el-table-column prop="points" label="扣分" width="100">
                    <template #default="{ row }">
                      <span class="neg">{{ row.points }}</span>
                      <span v-if="row.raw_points !== undefined && row.raw_points !== row.points" class="capped">
                        (原 {{ row.raw_points }}，已封顶)
                      </span>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
              <div v-else class="clean-tip">🎉 无扣分项，仓库基础完备！</div>
            </div>

            <!-- 完备度 + 风险概览 -->
            <div class="card">
              <h3>✅ 完备度检测</h3>
              <ul class="check-list">
                <li class="check-item">
                  <el-icon :size="18" :color="result.readiness.has_readme ? '#67c23a' : '#f56c6c'">
                    <component :is="result.readiness.has_readme ? 'CircleCheck' : 'CircleClose'" />
                  </el-icon>
                  README 文件
                  <el-tag :type="result.readiness.has_readme ? 'success' : 'danger'" size="small">
                    {{ result.readiness.has_readme ? '存在' : '缺失' }}
                  </el-tag>
                </li>
                <li class="check-item">
                  <el-icon :size="18" :color="result.readiness.found_dependency_files.length ? '#67c23a' : '#f56c6c'">
                    <component :is="result.readiness.found_dependency_files.length ? 'CircleCheck' : 'CircleClose'" />
                  </el-icon>
                  依赖清单
                  <el-tag v-if="result.readiness.found_dependency_files.length" type="success" size="small">
                    {{ result.readiness.found_dependency_files.join(', ') }}
                  </el-tag>
                  <el-tag v-else type="danger" size="small">未发现 package.json / pom.xml / requirements.txt / go.mod</el-tag>
                </li>
                <li class="check-item">
                  <el-icon :size="18" :color="result.risk_brief.windows_script_files.length ? '#e6a23c' : '#67c23a'">
                    <component :is="result.risk_brief.windows_script_files.length ? 'Warning' : 'CircleCheck'" />
                  </el-icon>
                  Windows 危险脚本 (.bat/.cmd/.ps1/.vbs)
                  <el-tag :type="result.risk_brief.windows_script_files.length ? 'warning' : 'success'" size="small">
                    {{ result.risk_brief.windows_script_files.length }} 个
                  </el-tag>
                </li>
              </ul>
              <!-- 文件名风险详情 -->
              <div v-if="result.risk_brief.windows_script_files.length" class="risk-sub">
                <h4>Windows 脚本文件列表</h4>
                <el-tag
                  v-for="f in result.risk_brief.windows_script_files"
                  :key="f"
                  type="warning"
                  effect="plain"
                  size="small"
                  class="tag-item"
                >{{ f }}</el-tag>
              </div>
            </div>
          </el-col>

          <!-- 右列：风险清单 + 内容扫描统计 -->
          <el-col :span="12">
            <!-- 内容扫描统计 -->
            <div class="card">
              <h3>🔬 内容扫描统计</h3>
              <el-descriptions :column="2" border size="small">
                <el-descriptions-item label="实际扫描文本文件">{{ result.content_scan.scanned_files }}</el-descriptions-item>
                <el-descriptions-item label="跳过文件">{{ result.content_scan.skipped_files.length }}</el-descriptions-item>
                <el-descriptions-item label="命中数">{{ result.content_scan.hits.length }}</el-descriptions-item>
                <el-descriptions-item label="风险条目">{{ result.summary.risk_items.length }}</el-descriptions-item>
              </el-descriptions>
            </div>

            <!-- 风险清单表格 -->
            <div class="card">
              <h3>⚠️ 风险清单</h3>
              <div v-if="result.summary.risk_items.length" class="risk-table-wrap">
                <!-- 风险等级过滤 -->
                <div class="filter-bar">
                  <span>等级过滤：</span>
                  <el-checkbox-group v-model="levelFilter" size="small">
                    <el-checkbox-button value="CRITICAL">CRITICAL</el-checkbox-button>
                    <el-checkbox-button value="HIGH">HIGH</el-checkbox-button>
                    <el-checkbox-button value="MEDIUM">MEDIUM</el-checkbox-button>
                    <el-checkbox-button value="LOW">LOW</el-checkbox-button>
                  </el-checkbox-group>
                </div>
                <el-table
                  :data="filteredRisks"
                  size="small"
                  stripe
                  border
                  max-height="360"
                  :empty-text="'当前过滤条件下无风险项'"
                >
                  <el-table-column label="等级" width="90">
                    <template #default="{ row }">
                      <el-tag :type="levelTag(row.level)" size="small" effect="dark">
                        {{ row.level }}
                      </el-tag>
                    </template>
                  </el-table-column>
                  <el-table-column label="类别" width="110">
                    <template #default="{ row }">
                      <el-tag :type="catTag(row.category)" size="small">
                        {{ catLabel(row.category) }}
                      </el-tag>
                    </template>
                  </el-table-column>
                  <el-table-column prop="file_path" label="文件" width="220">
                    <template #default="{ row }">
                      <el-tooltip
                        :content="row.file_path"
                        placement="top"
                        :show-after="200"
                      >
                        <span class="file-cell">{{ row.file_path }}</span>
                      </el-tooltip>
                    </template>
                  </el-table-column>
                  <el-table-column prop="detail" label="命中内容" min-width="260">
                    <template #default="{ row }">
                      <el-tooltip
                        :content="row.detail"
                        placement="top"
                        :show-after="200"
                      >
                        <span class="detail-cell">{{ row.detail }}</span>
                      </el-tooltip>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
              <div v-else class="clean-tip">🎉 未检测到风险项</div>
            </div>
          </el-col>
        </el-row>

        <!-- AI 接入建议（后端未返回该字段时不渲染，兼容旧版本） -->
        <div v-if="result.ai_advice" class="card ai-card">
          <h3>
            🤖 AI 接入建议
            <el-tag
              v-if="result.ai_advice.enabled && result.ai_advice.content"
              type="success"
              size="small"
              effect="plain"
              class="ai-tag"
            >{{ result.ai_advice.provider }}<span v-if="result.ai_advice.model"> · {{ result.ai_advice.model }}</span></el-tag>
            <el-tag v-else type="info" size="small" effect="plain" class="ai-tag">已禁用 / 降级</el-tag>
          </h3>

          <!-- 正常返回建议内容 -->
          <div v-if="result.ai_advice.enabled && result.ai_advice.content" class="ai-content">
            {{ result.ai_advice.content }}
          </div>

          <!-- 未配置密钥 / 调用失败时的提示（不影响基础扫描结果） -->
          <el-alert
            v-else
            :title="result.ai_advice.message || 'AI 建议不可用'"
            :description="result.ai_advice.error ? ('错误详情：' + result.ai_advice.error) : '配置 DEEPSEEK_API_KEY 后即可自动生成 AI 接入建议。'"
            type="info"
            :closable="false"
            show-icon
          />
        </div>
      </section>

      <!-- 未扫描空状态 -->
      <section v-else class="empty-state">
        <el-icon :size="72" color="#c0c4cc">📭</el-icon>
        <p>输入一个 GitHub / Gitee 公开仓库链接，点击"开始扫描"即可体检</p>
      </section>
    </main>

    <footer class="footer">
      Git 仓库接入体检工具 v0.1 — FastAPI + Vue3 + Element Plus
    </footer>
  </div>
</template>

<script setup>
import { ref, computed, nextTick, onMounted, watch } from 'vue'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'
import { startScanTask, getTaskStatus } from './api'

// ---------- 状态 ----------
const repoUrl = ref('')
const loading = ref(false)
const progress = ref(0)               // 单调递增，0-100
const progressText = ref('')          // 当前阶段文字
const result = ref(null)
const levelFilter = ref(['CRITICAL', 'HIGH', 'MEDIUM'])
const chartRef = ref(null)
let chartInstance = null

// 轮询定时器 + 兜底超时（全局唯一）
let pollTimer = null
let taskTimeoutTimer = null
const TASK_POLL_INTERVAL = 2000      // 2s 一次
const TASK_TIMEOUT_MS = 300_000       // 兜底 5 分钟（防止轮询卡死）

// ---------- 扫描主流程（异步任务 + 轮询） ----------
async function doScan() {
  const url = repoUrl.value.trim()
  if (!url) {
    ElMessage.warning('请输入 GitHub / Gitee 仓库链接')
    return
  }

  // 清理上一次的定时器（防竞争）
  stopPolling()

  loading.value = true
  progress.value = 0
  progressText.value = '提交扫描请求...'
  result.value = null

  try {
    // 1. POST /api/scan → 立即返回 task_id
    const taskInfo = await startScanTask(url)
    const taskId = taskInfo.task_id
    progress.value = Math.max(progress.value, taskInfo.progress || 5)
    progressText.value = taskInfo.progress_text || '任务已创建'

    // 2. 兜底超时：5 分钟后强制终止轮询
    clearTimeout(taskTimeoutTimer)
    taskTimeoutTimer = setTimeout(() => {
      if (loading.value) {
        stopPolling()
        loading.value = false
        progressText.value = '扫描超时（超过 5 分钟），请稍后再试'
        ElMessage.warning('扫描超时，任务已在后台继续运行，稍后可重新查询')
      }
    }, TASK_TIMEOUT_MS)

    // 3. 启动轮询（与任务并行）
    startPolling(taskId)
  } catch (_err) {
    // POST 阶段失败（链接校验/后端异常），拦截器已弹错
    stopPolling()
    loading.value = false
  }
}

function startPolling(taskId) {
  stopPolling()  // 先清掉旧的
  pollTimer = setInterval(async () => {
    try {
      const task = await getTaskStatus(taskId)

      // 单调递增进度（防止后端抖动回退）
      if (task.progress !== undefined && task.progress > progress.value) {
        progress.value = task.progress
      }
      if (task.progress_text) {
        progressText.value = task.progress_text
      }

      if (task.status === 'success') {
        // 成功：进度拉满 + 显示结果
        stopPolling()
        progress.value = 100
        progressText.value = '扫描完成'
        if (task.result) {
          result.value = task.result
          await nextTick()
          renderChart()
          ElMessage.success('扫描完成')
        }
        loading.value = false
      } else if (task.status === 'failed') {
        // 失败
        stopPolling()
        progressText.value = task.error || '扫描失败'
        ElMessage.error(task.error || '扫描失败')
        loading.value = false
      } else if (task.status === 'expired') {
        stopPolling()
        progressText.value = '任务已过期'
        loading.value = false
      }
      // running / pending → 继续轮询
    } catch (err) {
      // 轮询请求失败（网络抖动等），不终止轮询
      console.warn('[poll] 请求失败:', err.message)
    }
  }, TASK_POLL_INTERVAL)
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer)
    pollTimer = null
  }
  if (taskTimeoutTimer) {
    clearTimeout(taskTimeoutTimer)
    taskTimeoutTimer = null
  }
}

function reset() {
  stopPolling()
  loading.value = false
  progress.value = 0
  progressText.value = ''
  result.value = null
  repoUrl.value = ''
  destroyChart()
}

// ---------- 图表 ----------
function renderChart() {
  if (!chartRef.value || !result.value?.summary) return
  destroyChart()
  chartInstance = echarts.init(chartRef.value)
  const score = result.value.summary.score

  // 根据分数选颜色
  const color = score >= 80 ? '#67c23a' : score >= 60 ? '#e6a23c' : '#f56c6c'

  chartInstance.setOption({
    series: [
      {
        type: 'gauge',
        startAngle: 180,
        endAngle: 0,
        min: 0,
        max: 100,
        radius: '100%',
        progress: { show: true, width: 16, itemStyle: { color } },
        axisLine: { lineStyle: { width: 16, color: [[1, '#ebeef5']] } },
        pointer: { show: false },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        anchor: { show: false },
        title: { offsetCenter: [0, '10%'], fontSize: 12, color: '#909399' },
        detail: {
          offsetCenter: [0, '-15%'],
          fontSize: 48,
          fontWeight: 'bold',
          color,
          formatter: '{value}',
        },
        data: [{ value: score, name: '接入就绪度' }],
      },
    ],
  })
}

function destroyChart() {
  if (chartInstance) {
    chartInstance.dispose()
    chartInstance = null
  }
}

// ---------- 辅助函数 ----------
const riskTagType = computed(() => {
  if (!result.value) return ''
  return levelTag(result.value.summary.risk_level)
})

function levelTag(level) {
  return {
    CRITICAL: 'danger',
    HIGH: 'warning',
    MEDIUM: 'primary',
    LOW: 'info',
    CLEAN: 'success',
  }[level] || 'info'
}

function catTag(cat) {
  return {
    secret_key: 'danger',
    hardcoded_path: 'warning',
    windows_script: 'danger',
  }[cat] || 'info'
}

function catLabel(cat) {
  return {
    secret_key: '密钥泄露',
    hardcoded_path: '硬编码路径',
    windows_script: 'Windows脚本',
  }[cat] || cat
}

// ---------- 进度条颜色（随进度变化） ----------
const progressBarColor = computed(() => {
  const p = progress.value
  if (p >= 85) return '#67c23a'
  if (p >= 50) return '#409eff'
  if (p >= 25) return '#e6a23c'
  return '#909399'
})

const filteredRisks = computed(() => {
  if (!result.value) return []
  return result.value.summary.risk_items.filter((r) => levelFilter.value.includes(r.level))
})

// ---------- 生命周期 ----------
onMounted(() => {
  window.addEventListener('resize', () => chartInstance?.resize())
})

// result 变化时重新渲染图表
watch(result, () => {
  if (result.value) nextTick(renderChart)
  else destroyChart()
})
</script>

<style>
/* 全局样式（内联在组件里避免额外引入） */
* { box-sizing: border-box; }
body { margin: 0; font-family: -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: #f5f7fa; }
</style>

<style scoped>
.app { min-height: 100vh; display: flex; flex-direction: column; }

/* 头部 */
.header {
  background: linear-gradient(135deg, #409eff 0%, #337ecc 100%);
  color: #fff;
  padding: 28px 0 24px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}
.header-inner { max-width: 1200px; margin: 0 auto; padding: 0 24px; }
.header h1 { margin: 0 0 6px; font-size: 26px; font-weight: 600; letter-spacing: 0.5px; }
.subtitle { margin: 0; opacity: 0.85; font-size: 14px; }

/* 主体 */
.container {
  flex: 1;
  max-width: 1200px;
  width: 100%;
  margin: 0 auto;
  padding: 24px;
}

/* 通用卡片 */
.card {
  background: #fff;
  border-radius: 10px;
  padding: 20px 24px;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.06);
  margin-bottom: 20px;
}
.card h3 {
  margin: 0 0 16px;
  font-size: 16px;
  font-weight: 600;
  color: #303133;
  border-left: 3px solid #409eff;
  padding-left: 10px;
}
.card h4 { margin: 14px 0 8px; font-size: 13px; color: #606266; font-weight: 600; }

/* 输入卡 */
.input-card .el-form-item { margin-right: 16px; }

/* 进度条 */
.progress-box {
  margin-top: 20px;
  padding: 16px 20px;
  background: linear-gradient(135deg, #ecf5ff 0%, #f0f9eb 100%);
  border-radius: 8px;
  border: 1px solid #d9ecff;
}
.progress-box .el-progress { margin-bottom: 8px; }
.progress-text {
  font-size: 13px;
  color: #606266;
  text-align: center;
  min-height: 18px;
}

/* 结果区顶栏 */
.result-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 20px;
}
.repo-title h2 { margin: 0 0 8px; font-size: 22px; }
.repo-sep { margin: 0 4px; color: #909399; }
.repo-meta { font-size: 13px; color: #606266; }
.risk-badge { flex-shrink: 0; }

/* 仪表盘 */
.chart { width: 100%; height: 180px; }

/* 分数区间说明 */
.score-legend {
  margin-bottom: 10px;
  font-size: 13px;
  color: #606266;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
}
.legend-label { color: #909399; font-weight: 500; margin-right: 4px; }

/* tooltip 包裹的截断 span */
.file-cell,
.detail-cell {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  cursor: default;
}

/* 扣分明细 */
.deductions { margin-top: 14px; }
.neg { color: #f56c6c; font-weight: 600; }
.capped { color: #909399; font-size: 12px; }

/* 完备度列表 */
.check-list { list-style: none; padding: 0; margin: 0; }
.check-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid #f0f2f5;
  font-size: 14px;
}
.check-item:last-child { border-bottom: none; }

/* 风险详情 */
.risk-sub { margin-top: 8px; }
.tag-item { margin: 4px 4px 0 0; max-width: 260px; }

/* 风险表格 */
.filter-bar {
  margin-bottom: 10px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #606266;
}
.risk-table-wrap { margin-top: 0; }

/* AI 接入建议卡片 */
.ai-card { margin-top: 4px; }
.ai-card h3 { display: flex; align-items: center; gap: 8px; }
.ai-tag { font-weight: 400; }
.ai-content {
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 14px;
  line-height: 1.9;
  color: #303133;
  background: #fafcff;
  border: 1px solid #e4edf7;
  border-radius: 8px;
  padding: 14px 18px;
}

/* 空状态 */
.empty-state {
  text-align: center;
  padding: 80px 24px;
  color: #909399;
}
.empty-state p { margin-top: 16px; font-size: 14px; }

/* 干净状态（无风险/无扣分） */
.clean-tip {
  text-align: center;
  padding: 16px;
  background: #f0f9eb;
  color: #67c23a;
  border-radius: 6px;
  font-size: 14px;
}

/* 底部 */
.footer {
  text-align: center;
  padding: 16px;
  color: #909399;
  font-size: 12px;
  border-top: 1px solid #ebeef5;
}
</style>
