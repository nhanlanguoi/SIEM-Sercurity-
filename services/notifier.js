const axios = require('axios');

async function sendTelegram(message, config) {
  if (config.TELEGRAM_BOT_TOKEN === 'YOUR_BOT_TOKEN' || config.TELEGRAM_CHAT_ID === 'YOUR_CHAT_ID') {
    console.log('Chưa cấu hình Telegram Bot Token/Chat ID. Bỏ qua gửi tin nhắn.');
    console.log('Nội dung:', message);
    return;
  }

  try {
    const url = `https://api.telegram.org/bot${config.TELEGRAM_BOT_TOKEN}/sendMessage`;
    await axios.post(url, {
      chat_id: config.TELEGRAM_CHAT_ID,
      text: message
    });
  } catch (error) {
    console.error('Lỗi gửi cảnh báo Telegram:', error.message);
  }
}

module.exports = {
  sendTelegram
};
