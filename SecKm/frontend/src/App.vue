<template>
  <div class="app-root">
    <el-config-provider size="default">
      <AlertDashboard />
    </el-config-provider>
  </div>
</template>

<script setup lang="ts">
import AlertDashboard from './components/AlertDashboard.vue'
</script>

<style>
html,
body,
#app {
  margin: 0;
  min-height: 100%;
  background: #f8fafc;
  font-family: 'Helvetica Neue', Helvetica, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', Arial, sans-serif;
}

.app-root {
  min-height: 100vh;
}
</style>
