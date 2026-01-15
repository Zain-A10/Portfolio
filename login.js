// Demo credentials
const CORRECT_USERNAME = 'zain123';
const CORRECT_PASSWORD = 'password';
const ADDRESS = '18 Paddison Place';
const ZIP_CODE = 'L9R0J5';

document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('login-modal');
  const openBtn = document.getElementById('open-login');
  const closeBtn = document.getElementById('close-login');
  const form = document.getElementById('login-form');
  const statusEl = document.getElementById('status');
  const outputEl = document.getElementById('output');
  const usernameEl = document.getElementById('username');
  const passwordEl = document.getElementById('password');

  // Show the modal
  openBtn.addEventListener('click', () => {
    modal.classList.add('active');
    usernameEl.focus();
  });

  // Hide the modal
  closeBtn.addEventListener('click', () => {
    modal.classList.remove('active');
    form.reset();
    statusEl.textContent = '';
    outputEl.hidden = true;
  });

  // Handle login form
  form.addEventListener('submit', (e) => {
    e.preventDefault();

    const username = usernameEl.value.trim();
    const password = passwordEl.value;

    if (username === CORRECT_USERNAME && password === CORRECT_PASSWORD) {
      statusEl.textContent = 'Login successful!';
      statusEl.className = 'status ok';
      outputEl.innerHTML = `Address: ${ADDRESS}<br>Zip code: ${ZIP_CODE}`;
      outputEl.hidden = false;
    } else {
      statusEl.textContent = 'Incorrect login info. Please try again.';
      statusEl.className = 'status error';
      outputEl.hidden = true;
      passwordEl.value = '';
      passwordEl.focus();
    }
  });
});

// === Age verification with dropdowns ===
document.addEventListener('DOMContentLoaded', () => {
  const ageModal = document.getElementById('age-modal');
  const ageForm = document.getElementById('age-form');
  const ageStatus = document.getElementById('age-status');
  const ageExitBtn = document.getElementById('age-exit');

  const yearSelect = document.getElementById('year');
  const monthSelect = document.getElementById('month');
  const daySelect = document.getElementById('day');

  // Populate dropdowns
  const currentYear = new Date().getFullYear();
  for (let y = currentYear; y >= 1900; y--) {
    const opt = document.createElement('option');
    opt.value = y;
    opt.textContent = y;
    yearSelect.appendChild(opt);
  }
  const months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
  ];
  months.forEach((m, i) => {
    const opt = document.createElement('option');
    opt.value = i + 1;
    opt.textContent = m;
    monthSelect.appendChild(opt);
  });
  for (let d = 1; d <= 31; d++) {
    const opt = document.createElement('option');
    opt.value = d;
    opt.textContent = d;
    daySelect.appendChild(opt);
  }

  const alreadyVerified = sessionStorage.getItem('ageVerified') === 'true';
  if (!alreadyVerified) {
    ageModal.classList.add('active');
    document.body.classList.add('age-blocked');
  }

  function calcAge(year, month, day) {
    const today = new Date();
    const dob = new Date(year, month - 1, day);
    let age = today.getFullYear() - dob.getFullYear();
    const m = today.getMonth() - dob.getMonth();
    if (m < 0 || (m === 0 && today.getDate() < dob.getDate())) age--;
    return age;
  }

  ageForm?.addEventListener('submit', (e) => {
    e.preventDefault();
    const year = parseInt(yearSelect.value);
    const month = parseInt(monthSelect.value);
    const day = parseInt(daySelect.value);

    if (!year || !month || !day) {
      ageStatus.textContent = 'Please select your full date of birth.';
      ageStatus.className = 'status error';
      return;
    }

    const age = calcAge(year, month, day);

    if (age >= 19) {
      ageStatus.textContent = 'Verified. Welcome!';
      ageStatus.className = 'status ok';
      sessionStorage.setItem('ageVerified', 'true');
      setTimeout(() => {
        ageModal.classList.remove('active');
        document.body.classList.remove('age-blocked');
      }, 400);
    } else {
      ageStatus.textContent = 'You are not old enough to use this website.';
      ageStatus.className = 'status error';
      ageExitBtn.style.display = 'block';
      ageExitBtn.addEventListener('click', () => {
        window.location.href = 'https://www.google.com';
      }, { once: true });
    }
  });
});
