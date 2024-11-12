chrome.runtime.onInstalled.addListener(() => {
  console.log('URL Safety Analyzer installed');
  
  chrome.contextMenus.create({
      id: 'analyze-url',
      title: 'URL 안전성 분석',
      contexts: ['link']
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'analyze-url') {
      chrome.storage.local.set({ 'tempUrl': info.linkUrl });
      // 팝업 열기
      chrome.action.openPopup();
  }
});