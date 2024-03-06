const { chromium } = require('playwright');
const fs = require('fs').promises; // Использование Promise-версии модуля fs для асинхронного чтения

(async () => {
  try {
    const browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    // Логин
    await page.goto('http://localhost:8000/login');
    await page.fill('input[name="username"]', 'Sultan');
    await page.fill('input[name="password"]', 'asd');
    await page.click('input[value="Login"]');

    if (page.url() === 'http://localhost:8000/main') {
      console.log('Login test passed');
    } else {
      console.log('Login test failed');
    }

    await browser.close();
  } catch (error) {
    console.log(`Login test failed with error: ${error}`);
  }

  // Регистрация и верификация
  try {
    const browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    
    await page.goto('http://localhost:8000/register');

    
    await page.fill('input[name="username"]', 'TestUsesdr');
    await page.fill('input[name="email"]', 'testusesdr@example.com'); 
    await page.fill('input[name="password"]', 'testpasswordsdd');
    await page.click('input[value="Register"]');

   
    const verificationCode = await fs.readFile('code.txt', 'utf8'); 

    await page.goto('http://localhost:8000/verify');
    await page.fill('input[name="code"]', verificationCode.trim()); 
    await page.click('input[value="Submit"]');

    if (page.url() === 'http://localhost:8000/main') {
      console.log('Registration and verification test passed');
    } else {
      console.log('Registration and verification test failed');
    }

    await browser.close();
  } catch (error) {
    console.log(`Registration and verification test failed with error: ${error}`);
  }
})();
