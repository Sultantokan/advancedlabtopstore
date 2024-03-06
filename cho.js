const { chromium } = require('playwright');

(async () => {
  try {
    const browser = await chromium.launch({ headless: false });
    const page = await browser.newPage();

    // Предположим, вы хотите проверить успешный логин
    await page.goto('http://localhost:8000/login');
    await page.fill('input[name="username"]', 'Shoko');
    await page.fill('input[name="password"]', 'admin');
    await page.click('text=Login');

    // Проверка URL после логина
    if (page.url() === 'http://localhost:8000/login') {
      console.log('Login test passed');
    } else {
      console.log('Login test failed');
    }

    await browser.close();
  } catch (error) {
    console.log(`Test failed with error: ${error}`);
  }

})();


