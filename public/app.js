const App = (() => {
  const API = '';

  function showMessage(el, text, type = 'info') {
    if (!el) return;

    el.textContent = text || '';
    el.className = `message show ${type}`;
  }

  function hideMessage(el) {
    if (!el) {
      el = document.getElementById('message');
    }

    if (el) {
      el.className = 'message';
      el.textContent = '';
    }
  }

  async function api(path, options = {}) {
    const fetchOptions = {
      credentials: 'include',
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    };

    const res = await fetch(`${API}${path}`, fetchOptions);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      const err = new Error(
        data.error || res.statusText || 'Request failed'
      );

      err.status = res.status;
      err.data = data;

      throw err;
    }

    return data;
  }

  async function checkAuth() {
    return api('/api/auth/me');
  }

  // ==========================================
  // LOGIN / SIGNUP TABS
  // ==========================================

  function initTabs() {
    const tabs = document.querySelectorAll('.tab');

    const panels = {
      login: document.getElementById('loginPanel'),
      signup: document.getElementById('signupPanel')
    };

    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));

        tab.classList.add('active');

        Object.values(panels).forEach(panel => {
          panel?.classList.remove('active');
        });

        panels[tab.dataset.tab]?.classList.add('active');

        hideMessage();
      });
    });
  }

  // ==========================================
  // MAIN LOGIN PAGE
  // ==========================================

  function initLoginPage() {
    const roleSelection = document.getElementById('roleSelection');
    const userAuthSection = document.getElementById('userAuthSection');

    const userRoleBtn = document.getElementById('userRoleBtn');
    const adminRoleBtn = document.getElementById('adminRoleBtn');
    const backToRolesBtn = document.getElementById('backToRolesBtn');

    const msg = document.getElementById('userMessage');

    initTabs();

    checkAuth()
      .then(() => {
        window.location.href = '/dashboard.html';
      })
      .catch(() => {});

    userRoleBtn?.addEventListener('click', () => {
      if (roleSelection) {
        roleSelection.style.display = 'none';
      }

      if (userAuthSection) {
        userAuthSection.style.display = 'block';
      }
    });

    adminRoleBtn?.addEventListener('click', () => {
      window.location.href = '/admin-login.html';
    });

    backToRolesBtn?.addEventListener('click', () => {
      if (userAuthSection) {
        userAuthSection.style.display = 'none';
      }

      if (roleSelection) {
        roleSelection.style.display = 'block';
      }

      hideMessage(msg);
    });

    document.getElementById('loginResetBtn')?.addEventListener('click', () => {
      document.getElementById('loginEmail').value = '';
      document.getElementById('loginPassword').value = '';

      hideMessage(msg);
    });

    document.getElementById('signupResetBtn')?.addEventListener('click', () => {
      [
        'userName',
        'userEmail',
        'userPassword'
      ].forEach(id => {
        const input = document.getElementById(id);

        if (input) {
          input.value = '';
        }
      });

      hideMessage(msg);
    });

    // ------------------------------------------
    // USER SIGNUP
    // ------------------------------------------

    document.getElementById('signupPanel')?.addEventListener('submit', async e => {
      e.preventDefault();

      const btn = document.getElementById('signupBtn');

      if (btn) {
        btn.disabled = true;
      }

      hideMessage(msg);

      try {
        const fullName = document
          .getElementById('userName')
          .value
          .trim();

        const email = document
          .getElementById('userEmail')
          .value
          .trim();

        const password = document
          .getElementById('userPassword')
          .value;

        if (!fullName || !email || !password) {
          throw new Error('Please fill in all fields.');
        }

        if (password.length < 8) {
          throw new Error('Password must be at least 8 characters.');
        }

        const data = await api('/api/auth/signup', {
          method: 'POST',

          body: JSON.stringify({
            fullName,
            email,
            password
          })
        });

        showMessage(
          msg,
          data.message || 'Account created successfully.',
          'success'
        );

        setTimeout(() => {
          window.location.href =
            data.redirect ||
            '/email-otp.html?type=user';
        }, 700);

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );

      } finally {
        if (btn) {
          btn.disabled = false;
        }
      }
    });

    // ------------------------------------------
    // USER LOGIN
    // ------------------------------------------

    document.getElementById('loginPanel')?.addEventListener('submit', async e => {
      e.preventDefault();

      const btn = document.getElementById('loginBtn');

      if (btn) {
        btn.disabled = true;
      }

      hideMessage(msg);

      try {
        const email = document
          .getElementById('loginEmail')
          .value
          .trim();

        const password = document
          .getElementById('loginPassword')
          .value;

        if (!email || !password) {
          throw new Error(
            'Please enter your email and password.'
          );
        }

        const data = await api('/api/auth/login', {
          method: 'POST',

          body: JSON.stringify({
            email,
            password
          })
        });

        showMessage(
          msg,
          data.message || 'Login successful.',
          'success'
        );

        setTimeout(() => {
          window.location.href =
            data.redirect ||
            '/mfa.html';
        }, 500);

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );

      } finally {
        if (btn) {
          btn.disabled = false;
        }
      }
    });
  }

  // ==========================================
  // DIGIT-ONLY INPUT
  // ==========================================

  function restrictDigits(input) {
    input?.addEventListener('input', e => {
      e.target.value = e.target.value
        .replace(/\D/g, '')
        .slice(0, 6);
    });
  }

  // ==========================================
  // MFA / GOOGLE AUTHENTICATOR SETUP
  // ==========================================

  async function initSetupPage() {
    const msg = document.getElementById('message');
    const loading = document.getElementById('setupLoading');
    const content = document.getElementById('setupContent');

    try {
      const data = await api('/api/auth/setup-2fa');

      document.getElementById('qrCode').src = data.qrCode;
      document.getElementById('accountEmail').textContent = data.email;
      document.getElementById('secretKey').textContent = data.secret;

      loading.classList.add('hidden');
      content.classList.remove('hidden');

    } catch (err) {
      loading.classList.add('hidden');

      showMessage(
        msg,
        err.message,
        'error'
      );
    }

    restrictDigits(
      document.getElementById('setupCode')
    );

    document.getElementById('setupForm')?.addEventListener('submit', async e => {
      e.preventDefault();

      const btn = document.getElementById('setupBtn');

      btn.disabled = true;

      hideMessage(msg);

      try {
        const data = await api(
          '/api/auth/setup-2fa/verify',
          {
            method: 'POST',

            body: JSON.stringify({
              code: document
                .getElementById('setupCode')
                .value
            })
          }
        );

        showMessage(
          msg,
          data.message,
          'success'
        );

        setTimeout(() => {
          window.location.href =
            data.redirect ||
            '/dashboard.html';
        }, 600);

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );

      } finally {
        btn.disabled = false;
      }
    });
  }

  // ==========================================
  // TOTP COUNTDOWN
  // ==========================================

  function startTotpCountdown() {
    const el = document.getElementById('totpCountdown');

    if (!el) {
      return;
    }

    const update = () => {
      const remaining =
        30 - (Math.floor(Date.now() / 1000) % 30);

      el.textContent = String(remaining);
    };

    update();

    setInterval(update, 1000);
  }

  // ==========================================
  // MFA VERIFICATION
  // ==========================================

  function initMfaPage() {
    const msg = document.getElementById('message');
    const input = document.getElementById('otp');
    const btn = document.getElementById('verifyBtn');

    restrictDigits(input);
    startTotpCountdown();

    document.getElementById('mfaForm')?.addEventListener('submit', async e => {
      e.preventDefault();

      btn.disabled = true;

      hideMessage(msg);

      try {
        const data = await api(
          '/api/auth/verify-totp',
          {
            method: 'POST',

            body: JSON.stringify({
              code: input.value.trim()
            })
          }
        );

        showMessage(
          msg,
          data.message,
          'success'
        );

        setTimeout(() => {
          window.location.href =
            data.redirect ||
            '/dashboard.html';
        }, 400);

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );

      } finally {
        btn.disabled = false;
      }
    });
  }

  // ==========================================
  // USER DASHBOARD
  // ==========================================

  function initDashboardPage() {
    const msg = document.getElementById('message');

    checkAuth()
      .then(user => {
        document.getElementById('welcomeMsg').textContent =
          `Welcome back, ${user.fullName}!`;

        document.getElementById('userName').textContent =
          user.fullName;

        document.getElementById('userEmail').textContent =
          user.email;
      })
      .catch(() => {
        window.location.href = '/login.html';
      });

    document.getElementById('logoutBtn')?.addEventListener('click', async () => {
      try {
        await api(
          '/api/auth/logout',
          {
            method: 'POST',
            body: '{}'
          }
        );
      } finally {
        window.location.href = '/login.html';
      }
    });
  }

  // ==========================================
  // FORGOT PASSWORD
  // ==========================================

  function initForgotPage() {
    const params =
      new URLSearchParams(window.location.search);

    const type =
      params.get('type') === 'admin'
        ? 'admin'
        : 'user';

    const msg =
      document.getElementById('message');

    document.getElementById('forgotSubtitle').textContent =
      type === 'admin'
        ? 'Enter your administrator email and we will send a reset link.'
        : 'Enter your email and we will send a reset link.';

    document.getElementById('backLink').href =
      type === 'admin'
        ? '/admin-login.html'
        : '/login.html';

    document.getElementById('forgotForm')?.addEventListener('submit', async e => {
      e.preventDefault();

      const btn =
        document.getElementById('forgotBtn');

      btn.disabled = true;

      hideMessage(msg);

      try {
        const data = await api(
          '/api/password/forgot',
          {
            method: 'POST',

            body: JSON.stringify({
              email: document
                .getElementById('forgotEmail')
                .value
                .trim(),

              accountType: type
            })
          }
        );

        showMessage(
          msg,
          data.message,
          'success'
        );

        if (data.devResetUrl) {
          const link =
            document.createElement('a');

          link.href =
            data.devResetUrl;

          link.textContent =
            'Open local development reset link';

          link.className =
            'dev-link';

          msg.appendChild(
            document.createElement('br')
          );

          msg.appendChild(link);
        }

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );

      } finally {
        btn.disabled = false;
      }
    });
  }

  // ==========================================
  // RESET PASSWORD
  // ==========================================

  function initResetPage() {
    const params =
      new URLSearchParams(window.location.search);

    const token =
      params.get('token');

    const type =
      params.get('type') === 'admin'
        ? 'admin'
        : 'user';

    const msg =
      document.getElementById('message');

    if (!token) {
      showMessage(
        msg,
        'This password reset link is missing its token.',
        'error'
      );

      document.getElementById('resetBtn').disabled = true;

      return;
    }

    document.getElementById('resetForm')?.addEventListener('submit', async e => {
      e.preventDefault();

      const password =
        document.getElementById('newPassword').value;

      const confirm =
        document.getElementById('confirmPassword').value;

      const btn =
        document.getElementById('resetBtn');

      if (password !== confirm) {
        showMessage(
          msg,
          'Passwords do not match.',
          'error'
        );

        return;
      }

      btn.disabled = true;

      hideMessage(msg);

      try {
        const data = await api(
          '/api/password/reset',
          {
            method: 'POST',

            body: JSON.stringify({
              token,
              accountType: type,
              password
            })
          }
        );

        showMessage(
          msg,
          data.message,
          'success'
        );

        setTimeout(() => {
          window.location.href =
            data.redirect ||
            '/login.html';
        }, 900);

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );

      } finally {
        btn.disabled = false;
      }
    });
  }

  // ==========================================
  // ADMIN LOGIN
  // ==========================================

  function initAdminLoginPage() {
    const msg =
      document.getElementById('message');

    api('/api/admin/me')
      .then(() => {
        window.location.href =
          '/admin-dashboard.html';
      })
      .catch(() => {});

    document.getElementById('adminLoginForm')?.addEventListener('submit', async e => {
      e.preventDefault();

      const btn =
        document.getElementById('adminLoginBtn');

      btn.disabled = true;

      hideMessage(msg);

      try {
        const data = await api(
          '/api/admin/login',
          {
            method: 'POST',

            body: JSON.stringify({
              email: document
                .getElementById('adminEmail')
                .value
                .trim(),

              password:
                document
                  .getElementById('adminPassword')
                  .value
            })
          }
        );

        window.location.href =
          data.redirect ||
          '/admin-dashboard.html';

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );

      } finally {
        btn.disabled = false;
      }
    });
  }

  // ==========================================
  // ADMIN DASHBOARD
  // ==========================================

  async function initAdminDashboardPage() {
    const msg =
      document.getElementById('message');

    try {
      const admin =
        await api('/api/admin/me');

      document.getElementById('adminWelcome').textContent =
        `Signed in as ${admin.fullName} (${admin.email})`;

      await Promise.all([
        loadUsers(),
        loadAudit()
      ]);

    } catch {
      window.location.href =
        '/admin-login.html';

      return;
    }

    async function loadUsers() {
      try {
        const data =
          await api('/api/admin/users');

        const body =
          document.getElementById('usersBody');

        body.innerHTML = '';

        if (!data.users.length) {
          body.innerHTML =
            '<tr><td colspan="6" class="center-text">No users registered.</td></tr>';

          return;
        }

        data.users.forEach(user => {
          const tr =
            document.createElement('tr');

          addCell(
            tr,
            user.full_name
          );

          addCell(
            tr,
            user.email
          );

          const statusCell = addCell(tr, '');

          const status = document.createElement('span');

          status.textContent =
            user.is_active ? 'Active' : 'Disabled';

          status.className =
            user.is_active
              ? 'status active'
              : 'status disabled';

          statusCell.appendChild(status);

          addCell(
            tr,
            user.totp_enabled
              ? 'Enabled'
              : 'Not set'
          );

          addCell(
            tr,
            user.last_login_at
              ? formatDate(user.last_login_at)
              : 'Never'
          );

          const actionCell =
            document.createElement('td');

          const button =
            document.createElement('button');

          button.className =
            user.is_active
              ? 'btn-danger small-btn'
              : 'btn-signup small-btn';

          button.textContent =
            user.is_active
              ? 'Disable'
              : 'Enable';

          button.addEventListener('click', async () => {
            button.disabled = true;

            try {
              const result =
                await api(
                  `/api/admin/users/${user.id}/status`,
                  {
                    method: 'PATCH',

                    body: JSON.stringify({
                      enabled:
                        !user.is_active
                    })
                  }
                );

              showMessage(
                msg,
                result.message,
                'success'
              );

              await Promise.all([
                loadUsers(),
                loadAudit()
              ]);

            } catch (err) {
              showMessage(
                msg,
                err.message,
                'error'
              );

              button.disabled = false;
            }
          });

          actionCell.appendChild(button);
          tr.appendChild(actionCell);
          body.appendChild(tr);
        });

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );
      }
    }

    async function loadAudit() {
      try {
        const data =
          await api('/api/admin/audit');

        const body =
          document.getElementById('auditBody');

        body.innerHTML = '';

        if (!data.logs.length) {
          body.innerHTML =
            '<tr><td colspan="6" class="center-text">No activity recorded yet.</td></tr>';

          return;
        }

        data.logs.forEach(log => {
          const tr =
            document.createElement('tr');

          addCell(
            tr,
            formatDate(log.created_at)
          );

          addCell(
            tr,
            log.actor_type
          );

          addCell(
            tr,
            log.action
          );

          addCell(
            tr,
            log.target_email || '—'
          );

          addCell(
            tr,
            log.ip_address || '—'
          );

          addCell(
            tr,
            log.details || '—'
          );

          body.appendChild(tr);
        });

      } catch (err) {
        showMessage(
          msg,
          err.message,
          'error'
        );
      }
    }

    document
      .getElementById('refreshUsersBtn')
      ?.addEventListener(
        'click',
        loadUsers
      );

    document
      .getElementById('refreshAuditBtn')
      ?.addEventListener(
        'click',
        loadAudit
      );

    document
      .getElementById('adminLogoutBtn')
      ?.addEventListener('click', async () => {

        try {
          await api(
            '/api/admin/logout',
            {
              method: 'POST',
              body: '{}'
            }
          );
        } finally {
          window.location.href =
            '/admin-login.html';
        }
      });
  }

  // ==========================================
  // EMAIL OTP VERIFICATION
  // ==========================================

  async function initEmailOtpPage() {
    const form =
      document.getElementById('emailOtpForm');

    const input =
      document.getElementById('otpCode');

    const message =
      document.getElementById('message');

    const resendBtn =
      document.getElementById('resendOtpBtn');

    if (!form) return;

    const params =
      new URLSearchParams(
        window.location.search
      );

    const type =
      params.get('type') === 'admin'
        ? 'admin'
        : 'user';

    const title =
      document.getElementById('pageTitle');

    const subtitle =
      document.getElementById('pageSubtitle');

    if (type === 'admin') {
      if (title) {
        title.textContent =
          'Verify Administrator Email';
      }

      if (subtitle) {
        subtitle.textContent =
          'Enter the 6-digit code sent to the administrator email.';
      }
    } else {
      if (title) {
        title.textContent =
          'Verify Your Email';
      }

      if (subtitle) {
        subtitle.textContent =
          'Enter the 6-digit code sent to your email.';
      }
    }

    function showOtpMessage(
      text,
      isError = false
    ) {
      if (!message) return;

      message.textContent =
        text;

      message.className =
        `message show ${isError ? 'error' : 'success'}`;
    }

    restrictDigits(input);

    // ------------------------------------------
    // VERIFY EMAIL OTP
    // ------------------------------------------

    form.addEventListener(
      'submit',
      async event => {
        event.preventDefault();

        const code =
          input.value.trim();

        if (!/^\d{6}$/.test(code)) {
          showOtpMessage(
            'Enter the 6-digit verification code.',
            true
          );

          return;
        }

        const button =
          document.getElementById(
            'verifyOtpBtn'
          );

        if (button) {
          button.disabled = true;
          button.textContent =
            'Verifying...';
        }

        try {
          const data =
            await api(
              '/api/otp/verify',
              {
                method: 'POST',

                body: JSON.stringify({
                  code,
                  type
                })
              }
            );

          showOtpMessage(
            data.message ||
            'Email verified successfully.'
          );

          window.location.href =
            data.redirect ||
            `/setup-2fa.html?type=${type}`;

        } catch (error) {
          showOtpMessage(
            error.message ||
            'Verification failed.',
            true
          );

          if (button) {
            button.disabled = false;
            button.textContent =
              'Verify Email';
          }
        }
      }
    );

    // ------------------------------------------
    // RESEND EMAIL OTP
    // ------------------------------------------

    resendBtn?.addEventListener(
      'click',
      async () => {
        resendBtn.disabled = true;
        resendBtn.textContent =
          'Sending...';

        try {
          const data =
            await api(
              '/api/otp/resend',
              {
                method: 'POST',

                body: JSON.stringify({
                  type
                })
              }
            );

          showOtpMessage(
            data.message ||
            'A new verification code has been sent.'
          );

        } catch (error) {
          showOtpMessage(
            error.message ||
            'Unable to resend code.',
            true
          );
        }

        resendBtn.disabled = false;
        resendBtn.textContent =
          'Resend code';
      }
    );
  }

  // ==========================================
  // ADMIN MFA VERIFICATION
  // ==========================================

  async function initAdminMfaPage() {
    const form =
      document.getElementById(
        'adminMfaForm'
      );

    const input =
      document.getElementById(
        'adminMfaCode'
      );

    const message =
      document.getElementById(
        'message'
      );

    if (!form) return;

    function showAdminMfaMessage(
      text,
      isError = false
    ) {
      if (!message) return;

      message.textContent =
        text;

      message.className =
        `message show ${isError ? 'error' : 'success'}`;
    }

    restrictDigits(input);

    form.addEventListener(
      'submit',
      async event => {
        event.preventDefault();

        const code =
          input.value.trim();

        if (!/^\d{6}$/.test(code)) {
          showAdminMfaMessage(
            'Enter the 6-digit authenticator code.',
            true
          );

          return;
        }

        const button =
          document.getElementById(
            'adminMfaBtn'
          );

        if (button) {
          button.disabled = true;
          button.textContent =
            'Verifying...';
        }

        try {
          const data =
            await api(
              '/api/admin/verify-totp',
              {
                method: 'POST',

                body: JSON.stringify({
                  code
                })
              }
            );

          showAdminMfaMessage(
            data.message ||
            'MFA verification successful.'
          );

          window.location.href =
            data.redirect ||
            '/admin-dashboard.html';

        } catch (error) {
          showAdminMfaMessage(
            error.message ||
            'MFA verification failed.',
            true
          );

          if (button) {
            button.disabled = false;
            button.textContent =
              'Verify & Continue';
          }
        }
      }
    );
  }

  // ==========================================
  // HELPER FUNCTIONS
  // ==========================================

  function addCell(row, value) {
    const td =
      document.createElement('td');

    td.textContent =
      value;

    row.appendChild(td);

    return td;
  }

  function formatDate(value) {
    if (!value) {
      return '—';
    }

    return new Date(value).toLocaleString();
  }

  // ==========================================
  // PUBLIC API
  // ==========================================

  return {
    api,
    checkAuth,
    initLoginPage,
    initSetupPage,
    initMfaPage,
    initDashboardPage,
    initForgotPage,
    initResetPage,
    initAdminLoginPage,
    initAdminDashboardPage,
    initEmailOtpPage,
    initAdminMfaPage
  };

})();