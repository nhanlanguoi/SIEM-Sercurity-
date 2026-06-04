require('dotenv').config();
const axios = require('axios');

async function testTelegram() {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  console.log('Token:', token);
  console.log('Chat ID:', chatId);

  try {
    const url = `https://api.telegram.org/bot${token}/sendMessage`;
    console.log('Đang gửi request tới:', url);
    
    const response = await axios.post(url, {
      chat_id: chatId,
      text: '🔔 TEST: Đây là tin nhắn test từ hệ thống SIEM.',
      parse_mode: 'Markdown'
    });
    
    console.log('Gửi thành công! Phản hồi từ Telegram:');
    console.log(response.data);
  } catch (error) {
    console.error('LỖI GỬI TELEGRAM:');
    if (error.response) {
      console.error('Mã lỗi HTTP:', error.response.status);
      console.error('Chi tiết lỗi:', error.response.data);
    } else {
      console.error(error.message);
    }
  }
}

testTelegram();
