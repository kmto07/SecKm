<template>
  <div class="dashboard-shell">
    <aside class="sidebar">
      <div class="brand-panel">
        <div class="brand-mark">SA</div>
        <div class="brand-text">
          <div class="brand-title">网络告警研判平台</div>
          <div class="brand-subtitle">Sec_km</div>
        </div>
      </div>

      <el-menu
        :default-active="activeTab"
        class="side-nav"
        mode="vertical"
        @select="handleNavSelect"
      >
        <el-menu-item index="upload">
          <el-icon><UploadFilled /></el-icon>
          <span>批量上传研判</span>
        </el-menu-item>
        <el-menu-item index="chat">
          <el-icon><ChatDotRound /></el-icon>
          <span>智能对话助手</span>
        </el-menu-item>
        <el-menu-item index="history">
          <el-icon><Notebook /></el-icon>
          <span>研判历史记录</span>
        </el-menu-item>
      </el-menu>

      <div class="sidebar-footer">
        <el-tag type="success" effect="light">模型服务就绪</el-tag>
        <el-tag type="info" effect="light">API 已连接</el-tag>
      </div>
    </aside>

    <main class="content-area">

      <el-card class="module-card" shadow="never">
        <template #header>
          <div class="module-header">
            <div class="module-title">{{ moduleTitle }}</div>
            <div class="module-desc">{{ moduleDesc }}</div>
          </div>
        </template>

        <div v-if="activeTab === 'upload'" class="page-panel upload-page">
          <div v-if="summaryInfo" class="summary-bar">
            本次批量研判共 {{ summaryInfo.total }} 条，成功 {{ summaryInfo.success }} 条，失败 {{ summaryInfo.failed }} 条。
          </div>
          <el-upload
            drag
            :auto-upload="false"
            :file-list="fileList"
            :on-change="handleFileChange"
            :limit="1"
            accept=".csv,.txt,.json"
            class="upload-box"
          >
            <el-icon class="upload-icon"><UploadFilled /></el-icon>
            <div class="upload-hint">拖拽文件到此处，或点击选择文件上传</div>
            <template #tip>
              <div class="el-upload__tip">支持 CSV / TXT / JSON；系统将逐条解析并送入模型完成批量研判。</div>
            </template>
          </el-upload>
          <div class="button-row">
            <el-button type="primary" :loading="batchLoading" :disabled="!selectedFile" @click="startBatchAnalyze">开始批量研判</el-button>
          </div>
        </div>

        <div v-else-if="activeTab === 'chat'" class="page-panel chat-page">
          <div class="chat-area" ref="chatBoxRef">
            <div v-if="chatMessages.length === 0" class="empty-state">
              请输入单条网络日志，大模型将直接给出威胁等级、攻击类型与研判建议。
            </div>
            <div v-for="(item, index) in chatMessages" :key="index" class="chat-item" :class="item.role">
              <div class="chat-role">{{ item.role === 'user' ? '用户' : '模型' }}</div>
              <div class="chat-text">{{ item.content }}</div>
              <div v-if="item.threatLevel" class="chat-meta">{{ item.threatLevel }} · {{ item.attackType }}</div>
            </div>
          </div>

          <div class="chat-input-wrap">
            <el-input
              v-model="chatInput"
              type="textarea"
              :rows="4"
              resize="none"
              placeholder="粘贴单条网络日志，例如 HTTP 请求、五元组、请求体等"
              class="input-box"
            />
            <div class="button-row">
              <el-button type="primary" :loading="chatLoading" @click="sendChat">发送研判</el-button>
            </div>
          </div>
        </div>

        <div v-else class="page-panel history-page">
          <div class="toolbar">
            <el-input v-model="searchKeyword" placeholder="搜索端口、协议、威胁等级" clearable style="width: 300px;" />
            <el-button :loading="loadingHistory" @click="loadHistory">刷新</el-button>
          </div>

          <div class="table-wrap">
            <el-table :data="pagedHistory" height="100%" stripe border style="width: 100%; margin: 0 auto;">
              <el-table-column prop="created_at" label="时间" align="center" min-width="180" />
              <el-table-column prop="protocol" label="协议" align="center" min-width="120" />
              <el-table-column prop="dest_port" label="端口" align="center" min-width="120" />
              <el-table-column prop="threat_level" label="威胁等级" align="center" min-width="120">
                <template #default="scope">
                  <el-tag :type="tagType(scope.row.threat_level)">{{ scope.row.threat_level }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="操作" align="center" min-width="140" fixed="right">
                <template #default="scope">
                  <el-button link type="primary" @click="openReport(scope.row)">查看研判报告</el-button>
                </template>
              </el-table-column>
            </el-table>
          </div>

          <div class="pagination-row">
            <el-pagination
              background
              layout="total, prev, pager, next, jumper"
              :total="filteredHistory.length"
              :page-size="pageSize"
              v-model:current-page="currentPage"
            />
          </div>
        </div>
      </el-card>
    </main>

    <el-dialog v-model="reportVisible" title="研判报告" width="60%">
      <div v-if="reportDetail">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="时间">{{ reportDetail.created_at }}</el-descriptions-item>
          <el-descriptions-item label="威胁等级">
            <el-tag :type="tagType(reportDetail.threat_level)">{{ reportDetail.threat_level }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="端口">{{ reportDetail.dest_port }}</el-descriptions-item>
          <el-descriptions-item label="协议">{{ reportDetail.protocol }}</el-descriptions-item>
        </el-descriptions>

        <div class="report-section">
          <div class="section-title">大模型原始分析</div>
          <pre>{{ reportDetail.ai_raw_response }}</pre>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import axios from 'axios'
import { ElMessage, type UploadFile } from 'element-plus'
import { UploadFilled, ChatDotRound, Notebook } from '@element-plus/icons-vue'

const api = axios.create({ baseURL: 'http://127.0.0.1:9000' })
const activeTab = ref<'upload' | 'chat' | 'history'>('history') // 默认进入历史记录方便查看
const moduleTitle = computed(() => {
  if (activeTab.value === 'upload') return '批量上传研判'
  if (activeTab.value === 'chat') return '智能对话助手'
  return '研判历史记录'
})
const moduleDesc = computed(() => {
  if (activeTab.value === 'upload') return '上传日志文件后，系统会逐条解析并调用大模型完成批量告警研判。'
  if (activeTab.value === 'chat') return '直接输入单条网络日志，快速获取威胁等级、攻击类型与分析结论。'
  return '查看每条告警的基础信息、威胁等级与对应的大模型研判报告。'
})

const chatInput = ref('')
const chatLoading = ref(false)
const batchLoading = ref(false)
const searchKeyword = ref('')
const selectedFile = ref<File | null>(null)
const fileList = ref<UploadFile[]>([])
const chatBoxRef = ref<HTMLDivElement | null>(null)
const reportVisible = ref(false)
const reportDetail = ref<any>(null)
const historyList = ref<any[]>([])
const chatMessages = ref<Array<{ role: 'user' | 'ai'; content: string; threatLevel?: string; attackType?: string }>>([])
const currentPage = ref(1)
const pageSize = 10
const summaryInfo = ref<{ total: number; success: number; failed: number } | null>(null)
const loadingHistory = ref(false)


const scrollChatBottom = () => {
  requestAnimationFrame(() => {
    if (chatBoxRef.value) chatBoxRef.value.scrollTop = chatBoxRef.value.scrollHeight
  })
}

const normalizeThreat = (value?: string) => {
  if (value && ['高危', '中危', '低危', '安全'].includes(value)) return value
  return '低危'
}

const tagType = (level?: string) => {
  if (level === '高危') return 'danger'
  if (level === '中危') return 'warning'
  if (level === '安全') return 'success'
  return 'info'
}

const loadHistory = async () => {
  loadingHistory.value = true
  try {
    const { data } = await api.get('/api/v1/records')
    historyList.value = data
    if (currentPage.value > Math.max(1, Math.ceil(data.length / pageSize))) {
      currentPage.value = 1
    }
  } finally {
    loadingHistory.value = false
  }
}

const filteredHistory = computed(() => {
  const q = searchKeyword.value.trim().toLowerCase()
  if (!q) return historyList.value
  return historyList.value.filter(item => [item.dest_port, item.protocol, item.threat_level].join(' ').toLowerCase().includes(q))
})

const pagedHistory = computed(() => {
  const start = (currentPage.value - 1) * pageSize
  return filteredHistory.value.slice(start, start + pageSize)
})

const handleNavSelect = (index: string) => {
  activeTab.value = index as 'upload' | 'chat' | 'history'
}

const sendChat = async () => {
  if (!chatInput.value.trim()) return ElMessage.warning('请输入一条网络日志')
  const content = chatInput.value.trim()
  chatMessages.value.push({ role: 'user', content })
  chatInput.value = ''
  scrollChatBottom()
  chatLoading.value = true
  try {
    const { data } = await api.post('/api/v1/chat', { message: content })
    chatMessages.value.push({ role: 'ai', content: data.reply, threatLevel: normalizeThreat(data.threat_level), attackType: data.ai_attack_type || '未知' })
    ElMessage.success('研判完成')
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || '研判失败')
  } finally {
    chatLoading.value = false
    scrollChatBottom()
  }
}

const handleFileChange = (uploadFile: UploadFile) => {
  selectedFile.value = uploadFile.raw || null
  fileList.value = uploadFile.raw ? [uploadFile] : []
}

const startBatchAnalyze = async () => {
  if (!selectedFile.value) return ElMessage.warning('请先选择文件')
  batchLoading.value = true
  try {
    const formData = new FormData()
    formData.append('file', selectedFile.value)
    const { data } = await api.post('/api/v1/batch-analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    summaryInfo.value = { total: data.total, success: data.success_count, failed: data.failed_count }
    ElMessage.success(`批量研判完成：成功 ${data.success_count} 条，失败 ${data.failed_count} 条`)
    await loadHistory()
    activeTab.value = 'history'
  } catch (error: any) {
    ElMessage.error(error?.response?.data?.detail || '批量研判失败')
  } finally {
    batchLoading.value = false
  }
}

const openReport = async (row: any) => {
  try {
    const { data } = await api.get(`/api/v1/records/${row.id}`)
    reportDetail.value = data
    reportVisible.value = true
  } catch (error) {
    ElMessage.error('无法获取报告详情')
  }
}

onMounted(loadHistory)
</script>

<style scoped>
.dashboard-shell {
  height: 100vh;
  display: flex;
  gap: 18px;
  padding: 18px;
  background: radial-gradient(circle at top, #eef2ff 0%, #f8fafc 35%, #edf7ff 100%);
  box-sizing: border-box;
  overflow: hidden;
}

.sidebar {
  width: 250px;
  flex: 0 0 250px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  padding: 18px;
  border-radius: 20px;
  background: rgba(255, 255, 255, 0.72);
  backdrop-filter: blur(10px);
  box-shadow: 0 16px 38px rgba(15, 23, 42, 0.08);
  border: 1px solid rgba(226, 232, 240, 0.9);
}

.brand-panel {
  display: flex;
  align-items: center;
  gap: 12px;
}

.brand-mark {
  width: 52px;
  height: 52px;
  border-radius: 16px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 800;
  color: #fff;
  background: linear-gradient(135deg, #2563eb, #06b6d4);
  box-shadow: 0 10px 20px rgba(37, 99, 235, 0.25);
}

.brand-title {
  font-size: 16px;
  font-weight: 800;
  color: #0f172a;
}

.brand-subtitle {
  margin-top: 4px;
  color: #64748b;
  font-size: 12px;
}

.side-nav {
  flex: 1;
  border-right: none;
  background: transparent;
}

.side-nav :deep(.el-menu-item) {
  height: 54px;
  border-radius: 14px;
  margin-bottom: 10px;
  font-size: 14px;
  color: #334155;
}

.side-nav :deep(.el-menu-item.is-active) {
  background: linear-gradient(135deg, #eff6ff, #e0f2fe);
  color: #1d4ed8;
  font-weight: 700;
}

.sidebar-footer {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.content-area {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.module-card {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  border-radius: 20px;
  border: 1px solid rgba(226, 232, 240, 0.85);
  box-shadow: 0 12px 30px rgba(15, 23, 42, 0.06);
}

.module-card :deep(.el-card__body) {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
  padding: 20px;
}

.module-header,
.toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}

.module-desc {
  margin-top: 6px;
  color: #64748b;
  font-size: 13px;
}

.module-title {
  font-weight: 800;
  color: #0f172a;
  font-size: 18px;
}

.page-panel {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.summary-bar {
  margin-bottom: 12px;
  padding: 10px 12px;
  border-radius: 12px;
  background: #eef6ff;
  color: #1d4ed8;
  font-weight: 700;
}

.upload-page,
.history-page {
  gap: 12px;
}

.table-wrap {
  flex: 1;
  min-height: 0;
}

.chat-page {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 0;
}

.chat-area {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  border: 1px solid #e5e7eb;
  border-radius: 14px;
  padding: 14px;
  background: #fff;
}

.chat-input-wrap {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: auto;
}

.empty-state {
  color: #9ca3af;
  text-align: center;
  margin-top: 140px;
  line-height: 1.8;
  font-size: 13px;
}

.chat-item {
  padding: 12px;
  border-radius: 14px;
  margin-bottom: 10px;
  background: #f8fafc;
}

.chat-item.user {
  background: #dbeafe;
}

.chat-role {
  font-size: 11px;
  color: #64748b;
  margin-bottom: 6px;
  font-weight: 700;
}

.chat-text {
  white-space: pre-wrap;
  line-height: 1.6;
  color: #0f172a;
  font-size: 13px;
}

.chat-meta {
  margin-top: 8px;
  color: #334155;
  font-size: 11px;
  font-weight: 600;
}

.input-box {
  margin-top: 0;
}

.button-row {
  display: flex;
  justify-content: flex-end;
}

.upload-box :deep(.el-upload-dragger) {
  border-radius: 16px;
  border: 2px dashed #93c5fd;
  background: linear-gradient(180deg, #f8fbff, #eff6ff);
  padding: 28px;
}

.upload-icon {
  font-size: 48px;
  color: #2563eb;
}

.upload-hint {
  margin-top: 8px;
  font-weight: 700;
  color: #0f172a;
}

.pagination-row {
  display: flex;
  justify-content: flex-end;
}

.report-section {
  margin-top: 16px;
  background: #f8fafc;
  border-radius: 14px;
  padding: 14px;
}

.section-title {
  font-weight: 800;
  color: #0f172a;
  margin-bottom: 8px;
}

pre {
  white-space: pre-wrap;
  background: #f8fafc;
  padding: 12px;
  border-radius: 12px;
  margin: 0;
  color: #0f172a;
  line-height: 1.7;
  font-size: 13px;
}

@media (max-width: 1100px) {
  .dashboard-shell {
    flex-direction: column;
    height: auto;
    min-height: 100vh;
  }

  .sidebar {
    width: 100%;
    flex: none;
  }
}
</style>