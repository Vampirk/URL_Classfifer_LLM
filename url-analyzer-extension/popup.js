document.addEventListener('DOMContentLoaded', function() {
  const analyzer = new URLAnalyzer();
  const analyzeButton = document.getElementById('analyzeButton');
  const healthButton = document.getElementById('healthButton');
  const resetButton = document.getElementById('resetButton');
  const resultContainer = document.getElementById('resultContainer');
  const loadingSpinner = document.getElementById('loadingSpinner');
  const apiStatusElement = document.getElementById('apiStatus');

  async function checkApiStatus() {
      try {
          const response = await fetch('http://localhost:8000/health');
          const data = await response.json();
          
          apiStatusElement.innerHTML = data.status === 'healthy' 
              ? `✅ API 서버 연결됨 (GPU: ${data.gpu_memory_allocated})` 
              : '❌ API 서버 연결 실패';
          apiStatusElement.className = `status ${data.status === 'healthy' ? 'success' : 'error'}`;
          analyzeButton.disabled = data.status !== 'healthy';
          
          return data;
      } catch (error) {
          apiStatusElement.innerHTML = '❌ API 서버 연결 실패';
          apiStatusElement.className = 'status error';
          analyzeButton.disabled = true;
          return null;
      }
  }

  async function analyzeURL(url) {
      const response = await fetch('http://localhost:8000/analyze', {
          method: 'POST',
          headers: {
              'Content-Type': 'application/json',
          },
          body: JSON.stringify({ url })
      });

      if (!response.ok) {
          throw new Error(`API 요청 실패: ${response.statusText}`);
      }

      return await response.json();
  }

  // URL 분석 처리
  async function handleAnalysis(url) {
      try {
          loadingSpinner.style.display = 'block';
          resultContainer.innerHTML = '';
          analyzeButton.disabled = true;

          const data = await analyzeURL(url);
          
          if (data.status === 'completed' && data.result) {
              resultContainer.innerHTML = analyzer.formatAnalysisResult(data.result);
          } else if (data.error) {
              throw new Error(data.error);
          }
      } catch (error) {
          resultContainer.innerHTML = `
              <div class="error-message">
                  ❌ 분석 중 오류 발생:<br>
                  ${error.message}
              </div>
          `;
      } finally {
          loadingSpinner.style.display = 'none';
          analyzeButton.disabled = false;
      }
  }

  // 이벤트 리스너 설정
  analyzeButton.addEventListener('click', async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      await handleAnalysis(tab.url);
  });

  healthButton.addEventListener('click', async () => {
      const healthData = await checkApiStatus();
      if (healthData) {
          resultContainer.innerHTML = analyzer.formatHealthResult(healthData);
      }
  });

  resetButton.addEventListener('click', () => {
      resultContainer.innerHTML = '';
      checkApiStatus();
  });

  // 컨텍스트 메뉴로부터의 URL 처리
  chrome.storage.local.get(['tempUrl'], async function(result) {
      if (result.tempUrl) {
          await handleAnalysis(result.tempUrl);
          chrome.storage.local.remove('tempUrl');
      }
  });

  // 초기 API 상태 확인 및 주기적 체크
  checkApiStatus();
  setInterval(checkApiStatus, 30000);
});