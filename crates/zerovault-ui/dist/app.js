'use strict';

(() => {
  const tauriCore =
    window.__TAURI__ && window.__TAURI__.core ? window.__TAURI__.core : null;
  const tauriEvent =
    window.__TAURI__ && window.__TAURI__.event ? window.__TAURI__.event : null;

  async function invoke(cmd, args) {
    if (!tauriCore) {
      throw new Error('Tauri runtime IPC bridge unavailable');
    }
    return tauriCore.invoke(cmd, args || {});
  }

  const state = {
    status: null,
    activeTab: 'files',
    currentVirtualDir: '/',
    entries: [],
    conflicts: [],
    hwCaps: null,
    selectedProviderKind: 'fs',
    lastAutoRemoteId: 'local-1',
    mountPathDirty: false,
    routingDirty: false,
    routingRemoteSignature: '',
    dialogHandler: null,
    picker: {
      mode: 'folder',
      includeFiles: false,
      currentPath: '',
      parentPath: null,
      selectedFiles: new Set(),
      onConfirm: null,
    },
  };

  const els = {
    connectingView: document.getElementById('connectingView'),
    offlineAlert: document.getElementById('offlineAlert'),
    retryConnectBtn: document.getElementById('retryConnectBtn'),

    authView: document.getElementById('authView'),
    authSubtitle: document.getElementById('authSubtitle'),
    authModeBadge: document.getElementById('authModeBadge'),
    authHwStrip: document.getElementById('authHwStrip'),
    authErrorBanner: document.getElementById('authErrorBanner'),
    initVaultForm: document.getElementById('initVaultForm'),
    initPassInput: document.getElementById('initPassInput'),
    initPassConfirmInput: document.getElementById('initPassConfirmInput'),
    toggleInitPassBtn: document.getElementById('toggleInitPassBtn'),
    passStrengthFill: document.getElementById('passStrengthFill'),
    passStrengthLabel: document.getElementById('passStrengthLabel'),
    passMatchHint: document.getElementById('passMatchHint'),
    initSubmitBtn: document.getElementById('initSubmitBtn'),
    unlockVaultForm: document.getElementById('unlockVaultForm'),
    authVaultIdLabel: document.getElementById('authVaultIdLabel'),
    unlockPassInput: document.getElementById('unlockPassInput'),
    toggleUnlockPassBtn: document.getElementById('toggleUnlockPassBtn'),
    unlockSubmitBtn: document.getElementById('unlockSubmitBtn'),
    authBenchBtn: document.getElementById('authBenchBtn'),
    authQuitBtn: document.getElementById('authQuitBtn'),
    authBenchResult: document.getElementById('authBenchResult'),

    workspaceView: document.getElementById('workspaceView'),
    sidebarEngineBadge: document.getElementById('sidebarEngineBadge'),
    navDirtyBadge: document.getElementById('navDirtyBadge'),
    navRemoteBadge: document.getElementById('navRemoteBadge'),
    navMountDot: document.getElementById('navMountDot'),
    navConflictBadge: document.getElementById('navConflictBadge'),
    sidebarQuotaPct: document.getElementById('sidebarQuotaPct'),
    sidebarQuotaFill: document.getElementById('sidebarQuotaFill'),
    sidebarQuotaText: document.getElementById('sidebarQuotaText'),
    sidebarRevBadge: document.getElementById('sidebarRevBadge'),
    sidebarUpRate: document.getElementById('sidebarUpRate'),
    sidebarDownRate: document.getElementById('sidebarDownRate'),
    quitAppBtn: document.getElementById('quitAppBtn'),

    viewTitle: document.getElementById('viewTitle'),
    syncStatusPill: document.getElementById('syncStatusPill'),
    vaultIdPill: document.getElementById('vaultIdPill'),
    syncNowBtn: document.getElementById('syncNowBtn'),
    lockVaultBtn: document.getElementById('lockVaultBtn'),

    tabPanels: {
      files: document.getElementById('tab-files'),
      remotes: document.getElementById('tab-remotes'),
      mount: document.getElementById('tab-mount'),
      security: document.getElementById('tab-security'),
    },

    vaultBreadcrumbs: document.getElementById('vaultBreadcrumbs'),
    fileSearchInput: document.getElementById('fileSearchInput'),
    newFolderBtn: document.getElementById('newFolderBtn'),
    uploadFilesBtn: document.getElementById('uploadFilesBtn'),
    refreshFilesBtn: document.getElementById('refreshFilesBtn'),
    noRemotesHint: document.getElementById('noRemotesHint'),
    dropZone: document.getElementById('dropZone'),
    dropOverlay: document.getElementById('dropOverlay'),
    filesTableBody: document.getElementById('filesTableBody'),
    filesEmptyState: document.getElementById('filesEmptyState'),
    emptyUploadBtn: document.getElementById('emptyUploadBtn'),
    emptyFolderBtn: document.getElementById('emptyFolderBtn'),

    openAddRemoteBtn: document.getElementById('openAddRemoteBtn'),
    remotesGrid: document.getElementById('remotesGrid'),
    activePolicySummary: document.getElementById('activePolicySummary'),
    applyPolicyBtn: document.getElementById('applyPolicyBtn'),
    policyBackendsPicker: document.getElementById('policyBackendsPicker'),
    policyBackendsCheckboxes: document.getElementById('policyBackendsCheckboxes'),
    mirroredAckRow: document.getElementById('mirroredAckRow'),
    mirroredMinAckInput: document.getElementById('mirroredMinAckInput'),
    targetedConfigPane: document.getElementById('targetedConfigPane'),
    targetedDefaultSelect: document.getElementById('targetedDefaultSelect'),
    addPrefixRuleBtn: document.getElementById('addPrefixRuleBtn'),
    targetedRulesList: document.getElementById('targetedRulesList'),

    platformDriverLabel: document.getElementById('platformDriverLabel'),
    mountStatusPill: document.getElementById('mountStatusPill'),
    mountPathInput: document.getElementById('mountPathInput'),
    browseMountBtn: document.getElementById('browseMountBtn'),
    useMockVfsCheckbox: document.getElementById('useMockVfsCheckbox'),
    mountDriveBtn: document.getElementById('mountDriveBtn'),
    unmountDriveBtn: document.getElementById('unmountDriveBtn'),
    openMountFolderBtn: document.getElementById('openMountFolderBtn'),
    statBytesRead: document.getElementById('statBytesRead'),
    statBytesWritten: document.getElementById('statBytesWritten'),
    statChunksHydrated: document.getElementById('statChunksHydrated'),
    statCacheHits: document.getElementById('statCacheHits'),
    statRamCache: document.getElementById('statRamCache'),
    statPendingDirty: document.getElementById('statPendingDirty'),

    secBackendLabel: document.getElementById('secBackendLabel'),
    secCapsGrid: document.getElementById('secCapsGrid'),
    benchSizeSelect: document.getElementById('benchSizeSelect'),
    runBenchBtn: document.getElementById('runBenchBtn'),
    benchResultCard: document.getElementById('benchResultCard'),
    benchEncRate: document.getElementById('benchEncRate'),
    benchEncBar: document.getElementById('benchEncBar'),
    benchDecRate: document.getElementById('benchDecRate'),
    benchDecBar: document.getElementById('benchDecBar'),
    refreshConflictsBtn: document.getElementById('refreshConflictsBtn'),
    conflictsTableBody: document.getElementById('conflictsTableBody'),
    conflictsEmpty: document.getElementById('conflictsEmpty'),

    addRemoteModal: document.getElementById('addRemoteModal'),
    closeAddRemoteBtn: document.getElementById('closeAddRemoteBtn'),
    cancelAddRemoteBtn: document.getElementById('cancelAddRemoteBtn'),
    providerTabs: document.getElementById('providerTabs'),
    addRemoteForm: document.getElementById('addRemoteForm'),
    remoteIdInput: document.getElementById('remoteIdInput'),
    remoteQuotaInput: document.getElementById('remoteQuotaInput'),
    remoteRootLabel: document.getElementById('remoteRootLabel'),
    remoteRootInput: document.getElementById('remoteRootInput'),
    browseRemoteRootBtn: document.getElementById('browseRemoteRootBtn'),
    oauthFields: document.getElementById('oauthFields'),
    oauthPkceFields: document.getElementById('oauthPkceFields'),
    oauthTokenFields: document.getElementById('oauthTokenFields'),
    oauthClientIdInput: document.getElementById('oauthClientIdInput'),
    oauthClientSecretInput: document.getElementById('oauthClientSecretInput'),
    oauthAuthUrlInput: document.getElementById('oauthAuthUrlInput'),
    oauthTokenUrlInput: document.getElementById('oauthTokenUrlInput'),
    oauthRawTokenInput: document.getElementById('oauthRawTokenInput'),
    s3Fields: document.getElementById('s3Fields'),
    s3EndpointInput: document.getElementById('s3EndpointInput'),
    s3RegionInput: document.getElementById('s3RegionInput'),
    s3BucketInput: document.getElementById('s3BucketInput'),
    s3AccessKeyInput: document.getElementById('s3AccessKeyInput'),
    s3SecretKeyInput: document.getElementById('s3SecretKeyInput'),
    webdavFields: document.getElementById('webdavFields'),
    davEndpointInput: document.getElementById('davEndpointInput'),
    davUserInput: document.getElementById('davUserInput'),
    davPassInput: document.getElementById('davPassInput'),
    remotePolicySelect: document.getElementById('remotePolicySelect'),
    remotePrefixField: document.getElementById('remotePrefixField'),
    remotePrefixInput: document.getElementById('remotePrefixInput'),
    submitAddRemoteBtn: document.getElementById('submitAddRemoteBtn'),

    pickerModal: document.getElementById('pickerModal'),
    pickerTitle: document.getElementById('pickerTitle'),
    closePickerBtn: document.getElementById('closePickerBtn'),
    pickerUpBtn: document.getElementById('pickerUpBtn'),
    pickerPathInput: document.getElementById('pickerPathInput'),
    pickerGoBtn: document.getElementById('pickerGoBtn'),
    pickerNewDirBtn: document.getElementById('pickerNewDirBtn'),
    pickerNewDirBar: document.getElementById('pickerNewDirBar'),
    pickerNewDirNameInput: document.getElementById('pickerNewDirNameInput'),
    pickerCreateDirConfirmBtn: document.getElementById('pickerCreateDirConfirmBtn'),
    pickerCreateDirCancelBtn: document.getElementById('pickerCreateDirCancelBtn'),
    pickerQuickRoots: document.getElementById('pickerQuickRoots'),
    pickerEntries: document.getElementById('pickerEntries'),
    pickerSelectionLabel: document.getElementById('pickerSelectionLabel'),
    pickerCancelBtn: document.getElementById('pickerCancelBtn'),
    pickerConfirmBtn: document.getElementById('pickerConfirmBtn'),

    dialogModal: document.getElementById('dialogModal'),
    dialogTitle: document.getElementById('dialogTitle'),
    closeDialogBtn: document.getElementById('closeDialogBtn'),
    dialogForm: document.getElementById('dialogForm'),
    dialogMessage: document.getElementById('dialogMessage'),
    dialogInputWrap: document.getElementById('dialogInputWrap'),
    dialogInputLabel: document.getElementById('dialogInputLabel'),
    dialogInput: document.getElementById('dialogInput'),
    dialogCancelBtn: document.getElementById('dialogCancelBtn'),
    dialogConfirmBtn: document.getElementById('dialogConfirmBtn'),

    toastStack: document.getElementById('toastStack'),
  };

  function showToast(message, kind) {
    const toast = document.createElement('div');
    toast.className = 'toast' + (kind === 'ok' ? ' ok' : kind === 'error' ? ' error' : '');
    toast.textContent = String(message);
    els.toastStack.appendChild(toast);
    setTimeout(() => {
      toast.remove();
    }, 4500);
  }

  function showAuthError(message) {
    if (!message) {
      els.authErrorBanner.classList.add('hidden');
      els.authErrorBanner.textContent = '';
      return;
    }
    els.authErrorBanner.textContent = message;
    els.authErrorBanner.classList.remove('hidden');
  }

  function formatIsoTimestamp(iso) {
    if (!iso) return '--';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  }

  function hydrationBadgeClass(slug, isDir) {
    if (isDir) return 'pill';
    switch (slug) {
      case 'pinned':
        return 'pill pill-ok';
      case 'cached':
        return 'pill pill-info';
      case 'partially-hydrated':
        return 'pill pill-info';
      case 'dirty':
        return 'pill pill-warn';
      default:
        return 'pill';
    }
  }

  function evaluatePassphraseStrength(pass) {
    if (!pass) return { pct: 0, label: 'Enter passphrase', color: 'var(--danger)' };
    let score = 0;
    if (pass.length >= 8) score += 20;
    if (pass.length >= 12) score += 25;
    if (pass.length >= 16) score += 15;
    if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score += 15;
    if (/\d/.test(pass)) score += 10;
    if (/[^A-Za-z0-9]/.test(pass)) score += 15;
    const pct = Math.min(100, score);
    if (pct < 40) return { pct, label: 'Weak — add length & symbols', color: 'var(--danger)' };
    if (pct < 70) return { pct, label: 'Fair — longer recommended', color: 'var(--warn)' };
    if (pct < 90) return { pct, label: 'Strong', color: 'var(--accent)' };
    return { pct, label: 'Very Strong', color: 'var(--ok)' };
  }

  function updateStrengthMeter() {
    const p1 = els.initPassInput.value;
    const p2 = els.initPassConfirmInput.value;
    const s = evaluatePassphraseStrength(p1);
    els.passStrengthFill.style.width = s.pct + '%';
    els.passStrengthFill.style.backgroundColor = s.color;
    els.passStrengthLabel.textContent = s.label;

    if (!p2) {
      els.passMatchHint.textContent =
        'Derived locally via Argon2id (>= 64 MiB) + HKDF-SHA256';
      els.passMatchHint.className = 'tiny muted';
      els.passMatchHint.style.color = '';
    } else if (p1 === p2) {
      els.passMatchHint.textContent = 'Passphrases match';
      els.passMatchHint.className = 'tiny rate-down';
      els.passMatchHint.style.color = '';
    } else {
      els.passMatchHint.textContent = 'Passphrases do not match';
      els.passMatchHint.className = 'tiny';
      els.passMatchHint.style.color = 'var(--danger)';
    }
  }

  async function loadHardwareCaps() {
    try {
      const caps = await invoke('get_hardware_caps');
      state.hwCaps = caps;
      renderHardwareCaps(caps);
    } catch (err) {
      renderHardwareCapsError(String(err));
    }
  }

  function renderHardwareCaps(caps) {
    els.authHwStrip.replaceChildren();
    const badges = [
      { label: caps.arch, ok: true },
      { label: caps.aes_hw ? 'AES-NI / ARMv8 AES' : 'AES HW Missing', ok: caps.aes_hw },
      { label: caps.pclmul_hw ? 'PCLMULQDQ / PMULL' : 'GHASH HW Missing', ok: caps.pclmul_hw },
      { label: caps.vaes_hw ? 'VAES Active' : 'VAES N/A', ok: caps.vaes_hw },
    ];
    for (const b of badges) {
      const pill = document.createElement('span');
      pill.className = b.ok ? 'pill pill-ok' : 'pill';
      pill.textContent = b.label;
      els.authHwStrip.appendChild(pill);
    }

    els.secBackendLabel.textContent =
      caps.backend_name + ' (' + caps.arch + ') — Mandatory Hardware Gate: ' +
      (caps.mandatory_satisfied ? 'VERIFIED' : 'FAILED');

    const capItems = [
      { name: 'AES-NI / ARMv8 AES', active: caps.aes_hw },
      { name: 'PCLMULQDQ / PMULL', active: caps.pclmul_hw },
      { name: 'Vector AES (VAES)', active: caps.vaes_hw },
      { name: 'AVX2 Execution', active: caps.avx2_hw },
      { name: 'Mandatory Fail-Closed Gate', active: caps.mandatory_satisfied },
    ];
    els.secCapsGrid.replaceChildren();
    for (const item of capItems) {
      const card = document.createElement('div');
      card.className = 'cap-item';
      const label = document.createElement('span');
      label.textContent = item.name;
      const pill = document.createElement('span');
      pill.className = item.active ? 'pill pill-ok' : 'pill';
      pill.textContent = item.active ? 'Active' : 'No';
      card.append(label, pill);
      els.secCapsGrid.appendChild(card);
    }
  }

  function renderHardwareCapsError(msg) {
    els.authHwStrip.replaceChildren();
    const pill = document.createElement('span');
    pill.className = 'pill pill-danger';
    pill.textContent = msg;
    els.authHwStrip.appendChild(pill);
    els.secBackendLabel.textContent = msg;
  }

  function switchScreen(vm) {
    if (!vm || !vm.daemon_reachable) {
      els.connectingView.classList.remove('hidden');
      els.authView.classList.add('hidden');
      els.workspaceView.classList.add('hidden');
      if (vm && vm.error_message) {
        els.offlineAlert.textContent = vm.error_message;
        els.offlineAlert.classList.remove('hidden');
      } else {
        els.offlineAlert.classList.add('hidden');
      }
      return;
    }

    if (!vm.unlocked) {
      els.connectingView.classList.add('hidden');
      els.authView.classList.remove('hidden');
      els.workspaceView.classList.add('hidden');
      els.authModeBadge.textContent = vm.daemon_mode || 'Embedded Engine';

      if (!vm.vault_initialized) {
        els.authSubtitle.textContent = 'Create your local zero-knowledge vault to begin';
        els.initVaultForm.classList.remove('hidden');
        els.unlockVaultForm.classList.add('hidden');
      } else {
        els.authSubtitle.textContent = 'Enter your passphrase to derive master keys in RAM';
        els.authVaultIdLabel.textContent = vm.vault_id || '--';
        els.initVaultForm.classList.add('hidden');
        els.unlockVaultForm.classList.remove('hidden');
      }
      return;
    }

    const wasLocked = els.workspaceView.classList.contains('hidden');
    els.connectingView.classList.add('hidden');
    els.authView.classList.add('hidden');
    els.workspaceView.classList.remove('hidden');

    if (wasLocked) {
      state.currentVirtualDir = '/';
      state.mountPathDirty = false;
      state.routingDirty = false;
      refreshDirectory();
      refreshConflicts();
    }
  }

  function renderStatus(vm) {
    const prevUnlocked = state.status ? state.status.unlocked : false;
    state.status = vm;
    switchScreen(vm);

    if (!vm || !vm.daemon_reachable || !vm.unlocked) {
      if (prevUnlocked) {
        state.entries = [];
        state.conflicts = [];
      }
      return;
    }

    els.sidebarEngineBadge.textContent = vm.daemon_mode;
    els.syncStatusPill.textContent = vm.sync_state;
    els.syncStatusPill.className =
      vm.pending_dirty_ops > 0 ? 'pill pill-warn' : 'pill pill-ok';
    els.vaultIdPill.textContent = vm.vault_id ? vm.vault_id.slice(0, 8) + '...' : 'no-vault';
    els.vaultIdPill.title = vm.vault_id || '';

    els.sidebarQuotaPct.textContent = vm.quota_used_percent.toFixed(1) + '%';
    els.sidebarQuotaFill.style.width =
      Math.min(100, Math.max(0, vm.quota_used_percent)).toFixed(1) + '%';
    els.sidebarQuotaText.textContent = vm.quota_summary;
    els.sidebarRevBadge.textContent = 'rev ' + vm.manifest_revision;
    els.sidebarUpRate.textContent = '\u25B2 ' + vm.upload_rate;
    els.sidebarDownRate.textContent = '\u25BC ' + vm.download_rate;

    if (vm.pending_dirty_ops > 0) {
      els.navDirtyBadge.textContent = String(vm.pending_dirty_ops);
      els.navDirtyBadge.classList.remove('hidden');
    } else {
      els.navDirtyBadge.classList.add('hidden');
    }

    els.navRemoteBadge.textContent = String((vm.remotes || []).length);
    if (vm.mounted) {
      els.navMountDot.classList.add('mounted');
    } else {
      els.navMountDot.classList.remove('mounted');
    }

    if (vm.conflict_count > 0) {
      els.navConflictBadge.textContent = String(vm.conflict_count);
      els.navConflictBadge.classList.remove('hidden');
    } else {
      els.navConflictBadge.classList.add('hidden');
    }

    if ((vm.remotes || []).length === 0) {
      els.noRemotesHint.classList.remove('hidden');
    } else {
      els.noRemotesHint.classList.add('hidden');
    }

    renderRemotesGrid(vm.remotes || []);
    els.activePolicySummary.textContent = vm.routing_policy;

    const sig = (vm.remotes || []).map((r) => r.id).join(',');
    if (!state.routingDirty || sig !== state.routingRemoteSignature) {
      state.routingRemoteSignature = sig;
      syncRoutingEditorFromStatus(vm);
    }

    // Mount tab updates
    els.platformDriverLabel.textContent = vm.platform_vfs_label;
    els.mountStatusPill.textContent = vm.mounted
      ? 'Mounted at ' + (vm.mount_point || '')
      : 'Unmounted';
    els.mountStatusPill.className = vm.mounted ? 'pill pill-ok' : 'pill';
    els.mountDriveBtn.disabled = vm.mounted;
    els.unmountDriveBtn.disabled = !vm.mounted;

    if (!state.mountPathDirty) {
      els.mountPathInput.value = vm.mount_point || vm.default_mount_point || '';
    }

    els.statBytesRead.textContent = vm.bytes_read_label;
    els.statBytesWritten.textContent = vm.bytes_written_label;
    els.statChunksHydrated.textContent = String(vm.chunks_hydrated);
    els.statCacheHits.textContent = String(vm.cache_hits);
    els.statRamCache.textContent = vm.cache_ram_label;
    els.statPendingDirty.textContent = vm.pending_dirty_ops + ' ops';
  }

  async function refreshStatus() {
    try {
      const vm = await invoke('fetch_status');
      renderStatus(vm);
    } catch (err) {
      renderStatus({
        daemon_reachable: false,
        error_message: String(err),
      });
    }
  }

  function setActiveTab(tab) {
    state.activeTab = tab;
    const titles = {
      files: 'Vault Files',
      remotes: 'Cloud Remotes & Routing',
      mount: 'Virtual Drive Mount',
      security: 'Security, Crypto & Conflicts',
    };
    els.viewTitle.textContent = titles[tab] || 'Zerovault';

    document.querySelectorAll('.nav-item').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.tab === tab);
    });
    Object.entries(els.tabPanels).forEach(([key, panel]) => {
      panel.classList.toggle('hidden', key !== tab);
    });

    if (tab === 'files' && state.status && state.status.unlocked) {
      refreshDirectory();
    } else if (tab === 'security' && state.status && state.status.unlocked) {
      refreshConflicts();
    }
  }

  function renderBreadcrumbs() {
    els.vaultBreadcrumbs.replaceChildren();
    const parts = state.currentVirtualDir.split('/').filter(Boolean);

    const rootBtn = document.createElement('button');
    rootBtn.type = 'button';
    rootBtn.className = 'crumb-btn';
    rootBtn.textContent = 'Vault Root (/)';
    rootBtn.addEventListener('click', () => navigateVaultDir('/'));
    els.vaultBreadcrumbs.appendChild(rootBtn);

    let accum = '';
    for (const part of parts) {
      const sep = document.createElement('span');
      sep.className = 'crumb-sep';
      sep.textContent = '/';
      els.vaultBreadcrumbs.appendChild(sep);

      accum += '/' + part;
      const target = accum;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'crumb-btn';
      btn.textContent = part;
      btn.addEventListener('click', () => navigateVaultDir(target));
      els.vaultBreadcrumbs.appendChild(btn);
    }
  }

  function parentVirtualDir(path) {
    if (!path || path === '/') return '/';
    const idx = path.lastIndexOf('/');
    if (idx <= 0) return '/';
    return path.slice(0, idx);
  }

  function renderDirectoryEntries() {
    renderBreadcrumbs();
    const q = (els.fileSearchInput.value || '').trim().toLowerCase();
    const filtered = q
      ? state.entries.filter((e) => e.name.toLowerCase().includes(q))
      : state.entries;

    els.filesTableBody.replaceChildren();

    if (state.currentVirtualDir !== '/' && !q) {
      const upTr = document.createElement('tr');
      const upTd = document.createElement('td');
      upTd.colSpan = 5;
      const upBtn = document.createElement('button');
      upBtn.type = 'button';
      upBtn.className = 'entry-name-btn';
      upBtn.textContent = '.. (Parent Directory)';
      upBtn.addEventListener('click', () =>
        navigateVaultDir(parentVirtualDir(state.currentVirtualDir))
      );
      upTd.appendChild(upBtn);
      upTr.appendChild(upTd);
      els.filesTableBody.appendChild(upTr);
    }

    if (filtered.length === 0) {
      els.filesEmptyState.classList.remove('hidden');
      return;
    }
    els.filesEmptyState.classList.add('hidden');

    for (const entry of filtered) {
      const tr = document.createElement('tr');

      const nameTd = document.createElement('td');
      const nameBtn = document.createElement('button');
      nameBtn.type = 'button';
      nameBtn.className = 'entry-name-btn';
      const iconSpan = document.createElement('span');
      iconSpan.textContent = entry.is_dir ? '\uD83D\uDCC1' : '\uD83D\uDCC4';
      const labelSpan = document.createElement('span');
      labelSpan.textContent = entry.name;
      nameBtn.append(iconSpan, labelSpan);
      if (entry.is_dir) {
        nameBtn.addEventListener('click', () => navigateVaultDir(entry.virtual_path));
      } else {
        nameBtn.addEventListener('click', () => promptExportFile(entry));
      }
      nameTd.appendChild(nameBtn);

      const sizeTd = document.createElement('td');
      sizeTd.className = 'mono tiny muted';
      sizeTd.textContent = entry.size_label;

      const modTd = document.createElement('td');
      modTd.className = 'tiny muted';
      modTd.textContent = formatIsoTimestamp(entry.modified_at);
      modTd.title = entry.modified_at;

      const stateTd = document.createElement('td');
      const statePill = document.createElement('span');
      statePill.className = hydrationBadgeClass(entry.hydration, entry.is_dir);
      statePill.textContent = entry.hydration_label;
      stateTd.appendChild(statePill);

      const actionsTd = document.createElement('td');
      const actionsWrap = document.createElement('div');
      actionsWrap.className = 'row-actions';

      if (!entry.is_dir) {
        if (entry.pinned) {
          const unpinBtn = document.createElement('button');
          unpinBtn.type = 'button';
          unpinBtn.className = 'btn btn-sm';
          unpinBtn.textContent = 'Unpin';
          unpinBtn.addEventListener('click', () => runEntryAction('unpin_vault_entry', entry));
          actionsWrap.appendChild(unpinBtn);
        } else {
          const pinBtn = document.createElement('button');
          pinBtn.type = 'button';
          pinBtn.className = 'btn btn-sm';
          pinBtn.textContent = 'Pin';
          pinBtn.addEventListener('click', () => runEntryAction('pin_vault_entry', entry));
          actionsWrap.appendChild(pinBtn);
        }

        const dehydrateBtn = document.createElement('button');
        dehydrateBtn.type = 'button';
        dehydrateBtn.className = 'btn btn-sm';
        dehydrateBtn.textContent = 'Dehydrate';
        dehydrateBtn.disabled = entry.pinned;
        if (entry.pinned) {
          dehydrateBtn.title = 'Unpin file before dehydrating';
        }
        dehydrateBtn.addEventListener('click', () =>
          runEntryAction('dehydrate_vault_entry', entry)
        );

        const exportBtn = document.createElement('button');
        exportBtn.type = 'button';
        exportBtn.className = 'btn btn-sm btn-primary';
        exportBtn.textContent = 'Export';
        exportBtn.addEventListener('click', () => promptExportFile(entry));

        actionsWrap.append(dehydrateBtn, exportBtn);
      }

      const renameBtn = document.createElement('button');
      renameBtn.type = 'button';
      renameBtn.className = 'btn btn-sm';
      renameBtn.textContent = 'Rename';
      renameBtn.addEventListener('click', () => promptRenameEntry(entry));

      const deleteBtn = document.createElement('button');
      deleteBtn.type = 'button';
      deleteBtn.className = 'btn btn-sm btn-danger';
      deleteBtn.textContent = 'Delete';
      deleteBtn.addEventListener('click', () => promptDeleteEntry(entry));

      actionsWrap.append(renameBtn, deleteBtn);
      actionsTd.appendChild(actionsWrap);

      tr.append(nameTd, sizeTd, modTd, stateTd, actionsTd);
      els.filesTableBody.appendChild(tr);
    }
  }

  async function navigateVaultDir(virtualPath) {
    state.currentVirtualDir = virtualPath || '/';
    await refreshDirectory();
  }

  async function refreshDirectory() {
    if (!state.status || !state.status.unlocked) return;
    try {
      const listing = await invoke('list_vault_dir', {
        virtual_path: state.currentVirtualDir,
      });
      state.currentVirtualDir = listing.virtual_path;
      state.entries = listing.entries || [];
      renderDirectoryEntries();
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  async function runEntryAction(commandName, entry) {
    try {
      const msg = await invoke(commandName, { virtual_path: entry.virtual_path });
      showToast(msg, 'ok');
      await Promise.all([refreshDirectory(), refreshStatus()]);
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  function promptNewFolder() {
    openDialog({
      title: 'Create Encrypted Folder',
      message: 'Create a folder inside ' + state.currentVirtualDir,
      inputLabel: 'Folder Name',
      inputValue: '',
      placeholder: 'e.g. Finance',
      confirmLabel: 'Create Folder',
      danger: false,
      onConfirm: async (name) => {
        const trimmed = name.trim();
        if (!trimmed) {
          throw new Error('Folder name must not be empty');
        }
        const prefix = state.currentVirtualDir === '/' ? '' : state.currentVirtualDir;
        const msg = await invoke('create_vault_dir', {
          virtual_path: prefix + '/' + trimmed,
        });
        showToast(msg, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  function promptRenameEntry(entry) {
    openDialog({
      title: 'Rename Entry',
      message: 'Enter a new name (or full destination path) for "' + entry.name + '":',
      inputLabel: 'New Name or Path',
      inputValue: entry.name,
      placeholder: entry.name,
      confirmLabel: 'Rename',
      danger: false,
      onConfirm: async (newName) => {
        const trimmed = newName.trim();
        if (!trimmed) {
          throw new Error('New name must not be empty');
        }
        const msg = await invoke('rename_vault_entry', {
          virtual_path: entry.virtual_path,
          new_name_or_path: trimmed,
        });
        showToast(msg, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  function promptDeleteEntry(entry) {
    const desc = entry.is_dir
      ? 'Permanently delete encrypted folder "' +
        entry.name +
        '" and all files inside it?'
      : 'Permanently delete encrypted file "' + entry.name + '"?';
    openDialog({
      title: entry.is_dir ? 'Delete Folder' : 'Delete File',
      message: desc,
      inputLabel: null,
      confirmLabel: 'Delete',
      danger: true,
      onConfirm: async () => {
        const msg = await invoke('delete_vault_entry', {
          virtual_path: entry.virtual_path,
          recursive: entry.is_dir,
        });
        showToast(msg, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  function promptExportFile(entry) {
    openPicker({
      title: 'Export "' + entry.name + '" to Local Folder',
      mode: 'folder',
      confirmLabel: 'Export Here',
      onConfirm: async (destFolder) => {
        const msg = await invoke('export_vault_file', {
          virtual_path: entry.virtual_path,
          local_dest_path: destFolder,
        });
        showToast(msg, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  function promptUploadFiles() {
    openPicker({
      title: 'Select Local Files to Encrypt & Upload to ' + state.currentVirtualDir,
      mode: 'files',
      confirmLabel: 'Encrypt & Upload',
      onConfirm: async (localPaths) => {
        const msg = await invoke('import_local_files', {
          local_paths: localPaths,
          virtual_dir: state.currentVirtualDir,
        });
        showToast(msg, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  // Remotes & Routing
  function renderRemotesGrid(remotes) {
    els.remotesGrid.replaceChildren();
    if (!remotes.length) {
      const card = document.createElement('div');
      card.className = 'panel-card';
      const msg = document.createElement('p');
      msg.className = 'muted';
      msg.textContent =
        'No remote storage backends configured yet. Click "+ Add Cloud Remote" to connect Google Drive, OneDrive, Dropbox, S3, WebDAV, or a local encrypted folder.';
      card.appendChild(msg);
      els.remotesGrid.appendChild(card);
      return;
    }

    for (const r of remotes) {
      const card = document.createElement('div');
      card.className = 'remote-card';

      const head = document.createElement('div');
      head.className = 'remote-card-head';

      const titleWrap = document.createElement('div');
      titleWrap.className = 'remote-title-wrap';
      const dot = document.createElement('span');
      dot.className = 'status-dot' + (r.healthy ? ' mounted' : '');
      const title = document.createElement('span');
      title.className = 'remote-title';
      title.textContent = r.id;
      const kind = document.createElement('span');
      kind.className = 'pill pill-info';
      kind.textContent = r.kind;
      titleWrap.append(dot, title, kind);

      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn btn-sm btn-danger';
      removeBtn.textContent = 'Remove';
      removeBtn.addEventListener('click', () => {
        openDialog({
          title: 'Remove Cloud Remote',
          message:
            'Disconnect remote "' +
            r.id +
            '" (' +
            r.kind +
            ')? Existing encrypted blobs remain untouched on the provider.',
          inputLabel: null,
          confirmLabel: 'Remove',
          danger: true,
          onConfirm: async () => {
            const res = await invoke('remove_remote', { id: r.id });
            state.routingDirty = false;
            showToast(res, 'ok');
            await refreshStatus();
          },
        });
      });

      head.append(titleWrap, removeBtn);

      const meta = document.createElement('div');
      meta.className = 'tiny muted mono';
      meta.textContent = 'root: ' + r.root + ' \u00B7 latency: ' + r.latency_label;

      const track = document.createElement('div');
      track.className = 'progress-track';
      const fill = document.createElement('div');
      fill.className = 'progress-fill';
      const pct =
        r.total_bytes > 0 ? Math.min(100, (r.used_bytes / r.total_bytes) * 100) : 0;
      fill.style.width = pct.toFixed(1) + '%';
      track.appendChild(fill);

      const quotaLine = document.createElement('div');
      quotaLine.className = 'tiny mono muted';
      quotaLine.textContent = r.quota_label;

      card.append(head, meta, track, quotaLine);

      if (r.last_error) {
        const errBox = document.createElement('div');
        errBox.className = 'tiny';
        errBox.style.color = '#fecaca';
        errBox.textContent = r.last_error;
        card.appendChild(errBox);
      }

      els.remotesGrid.appendChild(card);
    }
  }

  function syncRoutingEditorFromStatus(vm) {
    const remotes = vm.remotes || [];
    const policy = vm.routing_policy_raw;
    let mode = 'pooled';
    let selectedBackends = remotes.map((r) => r.id);
    let minAck = 1;
    let defaultBackend = remotes[0] ? remotes[0].id : '';
    let rules = [];

    if (policy) {
      if (policy.QuotaPooled) {
        mode = 'pooled';
        selectedBackends = policy.QuotaPooled.pool_backends || selectedBackends;
      } else if (policy.Mirrored) {
        mode = 'mirrored';
        selectedBackends = policy.Mirrored.backends || selectedBackends;
        minAck = policy.Mirrored.min_ack || 1;
      } else if (policy.Targeted) {
        mode = 'targeted';
        defaultBackend = policy.Targeted.default_backend || defaultBackend;
        rules = policy.Targeted.prefix_routes || [];
      }
    }

    const radio = document.querySelector('input[name="policyMode"][value="' + mode + '"]');
    if (radio) radio.checked = true;

    renderRoutingBackendChoices(remotes, selectedBackends, minAck);
    renderTargetedEditor(remotes, defaultBackend, rules);
    updateRoutingEditorVisibility();
  }

  function renderRoutingBackendChoices(remotes, selectedIds, minAck) {
    els.policyBackendsCheckboxes.replaceChildren();
    const selectedSet = new Set(selectedIds);
    for (const r of remotes) {
      const label = document.createElement('label');
      label.className = 'checkbox-inline';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.name = 'policyBackendCheck';
      cb.value = r.id;
      cb.checked = selectedSet.has(r.id);
      cb.addEventListener('change', () => {
        state.routingDirty = true;
      });
      const text = document.createElement('span');
      text.textContent = r.id + ' (' + r.kind + ')';
      label.append(cb, text);
      els.policyBackendsCheckboxes.appendChild(label);
    }
    els.mirroredMinAckInput.value = String(Math.max(1, minAck));
  }

  function renderTargetedEditor(remotes, defaultBackend, rules) {
    els.targetedDefaultSelect.replaceChildren();
    for (const r of remotes) {
      const opt = document.createElement('option');
      opt.value = r.id;
      opt.textContent = r.id + ' (' + r.kind + ')';
      opt.selected = r.id === defaultBackend;
      els.targetedDefaultSelect.appendChild(opt);
    }

    els.targetedRulesList.replaceChildren();
    for (const [prefix, backend] of rules) {
      appendTargetedRuleRow(prefix, backend);
    }
  }

  function appendTargetedRuleRow(prefix, backendId) {
    const remotes = (state.status && state.status.remotes) || [];
    const row = document.createElement('div');
    row.className = 'rule-row';

    const prefixInput = document.createElement('input');
    prefixInput.type = 'text';
    prefixInput.placeholder = '/Photos';
    prefixInput.value = prefix || '';
    prefixInput.addEventListener('input', () => {
      state.routingDirty = true;
    });

    const select = document.createElement('select');
    for (const r of remotes) {
      const opt = document.createElement('option');
      opt.value = r.id;
      opt.textContent = r.id;
      opt.selected = r.id === backendId;
      select.appendChild(opt);
    }
    select.addEventListener('change', () => {
      state.routingDirty = true;
    });

    const removeBtn = document.createElement('button');
    removeBtn.type = 'button';
    removeBtn.className = 'btn btn-sm btn-danger';
    removeBtn.textContent = 'Remove';
    removeBtn.addEventListener('click', () => {
      state.routingDirty = true;
      row.remove();
    });

    row.append(prefixInput, select, removeBtn);
    els.targetedRulesList.appendChild(row);
  }

  function updateRoutingEditorVisibility() {
    const modeRadio = document.querySelector('input[name="policyMode"]:checked');
    const mode = modeRadio ? modeRadio.value : 'pooled';

    els.policyBackendsPicker.classList.toggle('hidden', mode === 'targeted');
    els.mirroredAckRow.classList.toggle('hidden', mode !== 'mirrored');
    els.targetedConfigPane.classList.toggle('hidden', mode !== 'targeted');
  }

  async function applyRoutingPolicy() {
    const modeRadio = document.querySelector('input[name="policyMode"]:checked');
    const mode = modeRadio ? modeRadio.value : 'pooled';

    const checkedBackends = Array.from(
      document.querySelectorAll('input[name="policyBackendCheck"]:checked')
    ).map((el) => el.value);

    const rules = Array.from(els.targetedRulesList.querySelectorAll('.rule-row')).map(
      (row) => {
        const pfx = row.querySelector('input').value.trim();
        const bk = row.querySelector('select').value;
        return [pfx, bk];
      }
    );

    const input = {
      mode,
      backends: checkedBackends,
      min_ack: Number.parseInt(els.mirroredMinAckInput.value || '1', 10) || 1,
      default_backend: els.targetedDefaultSelect.value || null,
      prefix_routes: rules,
    };

    try {
      els.applyPolicyBtn.disabled = true;
      const msg = await invoke('set_routing_policy', { input });
      state.routingDirty = false;
      showToast(msg, 'ok');
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.applyPolicyBtn.disabled = false;
    }
  }

  // Add Remote Modal
  const PROVIDER_DEFAULTS = {
    fs: { id: 'local-1', root: '', label: 'Local Storage Directory', showBrowse: true },
    s3: { id: 's3-main', root: 'zerovault', label: 'Bucket Key Prefix', showBrowse: false },
    webdav: { id: 'webdav-1', root: '/zerovault', label: 'Remote Subpath Prefix', showBrowse: false },
    gdrive: { id: 'gdrive-1', root: '/zerovault', label: 'Google Drive Folder Prefix', showBrowse: false },
    onedrive: { id: 'onedrive-1', root: '/zerovault', label: 'OneDrive Folder Prefix', showBrowse: false },
    dropbox: { id: 'dropbox-1', root: '/zerovault', label: 'Dropbox Folder Prefix', showBrowse: false },
  };

  function setRemoteProviderKind(kind) {
    const prevDefault = PROVIDER_DEFAULTS[state.selectedProviderKind];
    state.selectedProviderKind = kind;
    const def = PROVIDER_DEFAULTS[kind] || PROVIDER_DEFAULTS.fs;

    document.querySelectorAll('.provider-tab').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.kind === kind);
    });

    if (!els.remoteIdInput.value.trim() || els.remoteIdInput.value === state.lastAutoRemoteId) {
      els.remoteIdInput.value = def.id;
      state.lastAutoRemoteId = def.id;
    }

    if (
      !els.remoteRootInput.value.trim() ||
      (prevDefault && els.remoteRootInput.value === prevDefault.root)
    ) {
      els.remoteRootInput.value = def.root;
    }

    els.remoteRootLabel.textContent = def.label;
    els.browseRemoteRootBtn.classList.toggle('hidden', !def.showBrowse);

    const isOAuth = kind === 'gdrive' || kind === 'onedrive' || kind === 'dropbox';
    els.oauthFields.classList.toggle('hidden', !isOAuth);
    els.s3Fields.classList.toggle('hidden', kind !== 's3');
    els.webdavFields.classList.toggle('hidden', kind !== 'webdav');
  }

  function updateOAuthAuthModeFields() {
    const checked = document.querySelector('input[name="oauthAuthMode"]:checked');
    const mode = checked ? checked.value : 'pkce';
    els.oauthPkceFields.classList.toggle('hidden', mode !== 'pkce');
    els.oauthTokenFields.classList.toggle('hidden', mode !== 'token');
  }

  function openAddRemoteModal() {
    els.addRemoteForm.reset();
    els.remoteIdInput.value = '';
    els.remoteRootInput.value = '';
    setRemoteProviderKind('fs');
    updateOAuthAuthModeFields();
    els.remotePrefixField.classList.add('hidden');
    els.addRemoteModal.classList.remove('hidden');
  }

  function closeAddRemoteModal() {
    els.addRemoteModal.classList.add('hidden');
  }

  async function submitAddRemote(ev) {
    ev.preventDefault();
    const kind = state.selectedProviderKind;
    const id = els.remoteIdInput.value.trim();
    const root = els.remoteRootInput.value.trim();
    const quotaVal = els.remoteQuotaInput.value.trim();
    const quota_mib = quotaVal ? Number.parseInt(quotaVal, 10) : null;
    const policy = els.remotePolicySelect.value || null;
    const prefix = policy === 'targeted' ? els.remotePrefixInput.value.trim() || null : null;

    if (!id || !root) {
      showToast('Backend ID and root path/prefix are required', 'error');
      return;
    }

    const isOAuth = kind === 'gdrive' || kind === 'onedrive' || kind === 'dropbox';
    const oauthModeEl = document.querySelector('input[name="oauthAuthMode"]:checked');
    const oauthMode = oauthModeEl ? oauthModeEl.value : 'pkce';

    try {
      els.submitAddRemoteBtn.disabled = true;

      if (isOAuth && oauthMode === 'pkce') {
        const client_id = els.oauthClientIdInput.value.trim();
        if (!client_id) {
          throw new Error('OAuth2 Client ID is required for browser sign-in');
        }
        els.submitAddRemoteBtn.textContent = 'Waiting for Browser Sign-In...';
        showToast('Browser opened for OAuth2 PKCE authentication...', 'info');
        const msg = await invoke('oauth_login_remote', {
          params: {
            id,
            kind,
            root,
            client_id,
            client_secret: els.oauthClientSecretInput.value || null,
            auth_url: els.oauthAuthUrlInput.value.trim() || null,
            token_url: els.oauthTokenUrlInput.value.trim() || null,
            quota_mib,
            policy,
            prefix,
          },
        });
        showToast(msg, 'ok');
      } else {
        let endpoint = null;
        let bucket = null;
        let region = null;
        let username = null;
        let secret = null;

        if (kind === 's3') {
          endpoint = els.s3EndpointInput.value.trim() || null;
          bucket = els.s3BucketInput.value.trim() || null;
          region = els.s3RegionInput.value.trim() || null;
          username = els.s3AccessKeyInput.value.trim() || null;
          secret = els.s3SecretKeyInput.value || null;
          if (!bucket) {
            throw new Error('S3 bucket name is required');
          }
        } else if (kind === 'webdav') {
          endpoint = els.davEndpointInput.value.trim() || null;
          username = els.davUserInput.value.trim() || null;
          secret = els.davPassInput.value || null;
          if (!endpoint) {
            throw new Error('WebDAV server URL is required');
          }
        } else if (isOAuth) {
          username = els.oauthClientIdInput.value.trim() || null;
          secret = els.oauthRawTokenInput.value.trim() || null;
          if (!secret) {
            throw new Error('Paste an OAuth2 access token or token JSON bundle');
          }
        }

        const msg = await invoke('add_remote', {
          params: {
            id,
            kind,
            root,
            endpoint,
            bucket,
            region,
            quota_mib,
            policy,
            prefix,
            username,
            secret,
          },
        });
        showToast(msg, 'ok');
      }

      closeAddRemoteModal();
      state.routingDirty = false;
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.submitAddRemoteBtn.disabled = false;
      els.submitAddRemoteBtn.textContent = 'Connect Backend';
    }
  }

  // Conflicts & Benchmarks
  async function refreshConflicts() {
    if (!state.status || !state.status.unlocked) return;
    try {
      const list = await invoke('list_conflicts');
      state.conflicts = list || [];
      renderConflicts();
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  function renderConflicts() {
    els.conflictsTableBody.replaceChildren();
    if (!state.conflicts.length) {
      els.conflictsEmpty.classList.remove('hidden');
      return;
    }
    els.conflictsEmpty.classList.add('hidden');
    for (const c of state.conflicts) {
      const tr = document.createElement('tr');
      const tdOrig = document.createElement('td');
      tdOrig.className = 'mono tiny';
      tdOrig.textContent = c.original_path;
      const tdCopy = document.createElement('td');
      tdCopy.className = 'mono tiny';
      tdCopy.textContent = c.conflict_path;
      const tdRev = document.createElement('td');
      tdRev.className = 'mono';
      tdRev.textContent = 'rev ' + c.remote_revision;
      const tdTime = document.createElement('td');
      tdTime.className = 'tiny muted';
      tdTime.textContent = formatIsoTimestamp(c.detected_at);
      tr.append(tdOrig, tdCopy, tdRev, tdTime);
      els.conflictsTableBody.appendChild(tr);
    }
  }

  async function executeBenchmark(mib, target) {
    try {
      const report = await invoke('run_crypto_benchmark', { mib });
      if (target === 'auth') {
        els.authBenchResult.textContent =
          'Hardware ' +
          report.caps.backend_name +
          ' (' +
          report.total_mib +
          ' MiB): Encrypt ' +
          report.encrypt_mib_per_sec.toFixed(1) +
          ' MiB/s \u00B7 Decrypt+Verify ' +
          report.decrypt_mib_per_sec.toFixed(1) +
          ' MiB/s';
        els.authBenchResult.classList.remove('hidden');
      } else {
        els.benchResultCard.classList.remove('hidden');
        els.benchEncRate.textContent =
          report.encrypt_mib_per_sec.toFixed(2) +
          ' MiB/s (' +
          report.encrypt_elapsed_ms +
          ' ms)';
        els.benchDecRate.textContent =
          report.decrypt_mib_per_sec.toFixed(2) +
          ' MiB/s (' +
          report.decrypt_elapsed_ms +
          ' ms)';
        const maxRate = Math.max(report.encrypt_mib_per_sec, report.decrypt_mib_per_sec, 1000);
        els.benchEncBar.style.width =
          Math.min(100, (report.encrypt_mib_per_sec / maxRate) * 100).toFixed(1) + '%';
        els.benchDecBar.style.width =
          Math.min(100, (report.decrypt_mib_per_sec / maxRate) * 100).toFixed(1) + '%';
      }
      showToast(
        'AES-256-GCM benchmark completed (' +
          report.decrypt_mib_per_sec.toFixed(1) +
          ' MiB/s decrypt)',
        'ok'
      );
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  // Local Picker Modal
  function openPicker(opts) {
    state.picker.mode = opts.mode || 'folder';
    state.picker.includeFiles = opts.mode === 'files';
    state.picker.selectedFiles = new Set();
    state.picker.onConfirm = opts.onConfirm;
    els.pickerTitle.textContent = opts.title || 'Select Path';
    els.pickerConfirmBtn.textContent = opts.confirmLabel || 'Select';
    els.pickerNewDirBar.classList.add('hidden');
    els.pickerModal.classList.remove('hidden');
    loadPickerDir(opts.initialPath || null);
  }

  function closePicker() {
    els.pickerModal.classList.add('hidden');
    state.picker.onConfirm = null;
  }

  async function loadPickerDir(path) {
    try {
      const listing = await invoke('browse_local_fs', {
        path: path || null,
        include_files: state.picker.includeFiles,
      });
      state.picker.currentPath = listing.current_path;
      state.picker.parentPath = listing.parent_path || null;
      els.pickerPathInput.value = listing.current_path;
      els.pickerUpBtn.disabled = !listing.parent_path;

      els.pickerQuickRoots.replaceChildren();
      for (const root of listing.quick_roots || []) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'picker-root-btn';
        btn.textContent = root.label;
        btn.title = root.path;
        btn.addEventListener('click', () => loadPickerDir(root.path));
        els.pickerQuickRoots.appendChild(btn);
      }

      els.pickerEntries.replaceChildren();
      const entries = listing.entries || [];
      if (!entries.length) {
        const empty = document.createElement('div');
        empty.className = 'empty-inline muted';
        empty.textContent = state.picker.includeFiles
          ? 'No subfolders or files here'
          : 'No subfolders here';
        els.pickerEntries.appendChild(empty);
      } else {
        for (const item of entries) {
          const row = document.createElement('div');
          row.className =
            'picker-row' +
            (state.picker.selectedFiles.has(item.path) ? ' selected' : '');

          if (!item.is_dir && state.picker.mode === 'files') {
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = state.picker.selectedFiles.has(item.path);
            cb.addEventListener('click', (e) => e.stopPropagation());
            cb.addEventListener('change', () => {
              if (cb.checked) state.picker.selectedFiles.add(item.path);
              else state.picker.selectedFiles.delete(item.path);
              row.classList.toggle('selected', cb.checked);
              updatePickerSelectionLabel();
            });
            row.appendChild(cb);
          }

          const icon = document.createElement('span');
          icon.textContent = item.is_dir ? '\uD83D\uDCC1' : '\uD83D\uDCC4';
          const name = document.createElement('span');
          name.className = 'picker-row-name';
          name.textContent = item.name;
          const size = document.createElement('span');
          size.className = 'tiny muted mono';
          size.textContent = item.size_label;

          row.append(icon, name, size);
          row.addEventListener('click', () => {
            if (item.is_dir) {
              loadPickerDir(item.path);
            } else if (state.picker.mode === 'files') {
              const selected = state.picker.selectedFiles.has(item.path);
              if (selected) state.picker.selectedFiles.delete(item.path);
              else state.picker.selectedFiles.add(item.path);
              const cb = row.querySelector('input[type="checkbox"]');
              if (cb) cb.checked = !selected;
              row.classList.toggle('selected', !selected);
              updatePickerSelectionLabel();
            }
          });
          els.pickerEntries.appendChild(row);
        }
      }
      updatePickerSelectionLabel();
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  function updatePickerSelectionLabel() {
    if (state.picker.mode === 'files') {
      const count = state.picker.selectedFiles.size;
      els.pickerSelectionLabel.textContent = count + ' file(s) selected';
      els.pickerConfirmBtn.disabled = count === 0;
    } else {
      els.pickerSelectionLabel.textContent = 'Folder: ' + state.picker.currentPath;
      els.pickerConfirmBtn.disabled = !state.picker.currentPath;
    }
  }

  async function confirmPickerSelection() {
    const fn = state.picker.onConfirm;
    if (!fn) return;
    const payload =
      state.picker.mode === 'files'
        ? Array.from(state.picker.selectedFiles)
        : state.picker.currentPath;
    closePicker();
    try {
      await fn(payload);
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  // Dialog Modal
  function openDialog(opts) {
    state.dialogHandler = opts.onConfirm;
    els.dialogTitle.textContent = opts.title || 'Confirm';
    els.dialogMessage.textContent = opts.message || '';
    if (opts.inputLabel) {
      els.dialogInputWrap.classList.remove('hidden');
      els.dialogInputLabel.textContent = opts.inputLabel;
      els.dialogInput.value = opts.inputValue || '';
      els.dialogInput.placeholder = opts.placeholder || '';
    } else {
      els.dialogInputWrap.classList.add('hidden');
      els.dialogInput.value = '';
    }
    els.dialogConfirmBtn.textContent = opts.confirmLabel || 'Confirm';
    els.dialogConfirmBtn.className = opts.danger ? 'btn btn-danger' : 'btn btn-primary';
    els.dialogModal.classList.remove('hidden');
    if (opts.inputLabel) {
      setTimeout(() => els.dialogInput.focus(), 30);
    }
  }

  function closeDialog() {
    els.dialogModal.classList.add('hidden');
    state.dialogHandler = null;
  }

  // Event Bindings
  els.retryConnectBtn.addEventListener('click', refreshStatus);

  els.toggleInitPassBtn.addEventListener('click', () => {
    const show = els.initPassInput.type === 'password';
    els.initPassInput.type = show ? 'text' : 'password';
    els.initPassConfirmInput.type = show ? 'text' : 'password';
    els.toggleInitPassBtn.textContent = show ? 'Hide' : 'Show';
  });

  els.toggleUnlockPassBtn.addEventListener('click', () => {
    const show = els.unlockPassInput.type === 'password';
    els.unlockPassInput.type = show ? 'text' : 'password';
    els.toggleUnlockPassBtn.textContent = show ? 'Hide' : 'Show';
  });

  els.initPassInput.addEventListener('input', updateStrengthMeter);
  els.initPassConfirmInput.addEventListener('input', updateStrengthMeter);

  els.initVaultForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    showAuthError('');
    const pass = els.initPassInput.value;
    const confirm = els.initPassConfirmInput.value;
    if (!pass) {
      showAuthError('Vault passphrase must not be empty');
      return;
    }
    if (pass !== confirm) {
      showAuthError('Passphrase confirmation does not match');
      return;
    }
    try {
      els.initSubmitBtn.disabled = true;
      els.initSubmitBtn.textContent = 'Deriving Argon2id Keys...';
      const msg = await invoke('init_vault', { passphrase: pass });
      els.initPassInput.value = '';
      els.initPassConfirmInput.value = '';
      showToast(msg, 'ok');
      await refreshStatus();
    } catch (err) {
      showAuthError(String(err));
    } finally {
      els.initSubmitBtn.disabled = false;
      els.initSubmitBtn.textContent = 'Create & Unlock Encrypted Vault';
    }
  });

  els.unlockVaultForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    showAuthError('');
    const pass = els.unlockPassInput.value;
    if (!pass) {
      showAuthError('Enter your master passphrase');
      return;
    }
    try {
      els.unlockSubmitBtn.disabled = true;
      els.unlockSubmitBtn.textContent = 'Deriving Keys...';
      const msg = await invoke('unlock_vault', { passphrase: pass });
      els.unlockPassInput.value = '';
      showToast(msg, 'ok');
      await refreshStatus();
    } catch (err) {
      showAuthError(String(err));
    } finally {
      els.unlockSubmitBtn.disabled = false;
      els.unlockSubmitBtn.textContent = 'Unlock Vault';
    }
  });

  els.authBenchBtn.addEventListener('click', () => executeBenchmark(32, 'auth'));
  els.authQuitBtn.addEventListener('click', () => invoke('quit_app'));
  els.quitAppBtn.addEventListener('click', () => invoke('quit_app'));

  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.addEventListener('click', () => setActiveTab(btn.dataset.tab));
  });

  els.syncNowBtn.addEventListener('click', async () => {
    try {
      els.syncNowBtn.disabled = true;
      const msg = await invoke('sync_now');
      showToast(msg, 'ok');
      await Promise.all([refreshStatus(), refreshDirectory(), refreshConflicts()]);
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.syncNowBtn.disabled = false;
    }
  });

  els.lockVaultBtn.addEventListener('click', async () => {
    try {
      els.lockVaultBtn.disabled = true;
      const msg = await invoke('lock_vault');
      showToast(msg, 'ok');
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.lockVaultBtn.disabled = false;
    }
  });

  els.fileSearchInput.addEventListener('input', renderDirectoryEntries);
  els.newFolderBtn.addEventListener('click', promptNewFolder);
  els.emptyFolderBtn.addEventListener('click', promptNewFolder);
  els.uploadFilesBtn.addEventListener('click', promptUploadFiles);
  els.emptyUploadBtn.addEventListener('click', promptUploadFiles);
  els.refreshFilesBtn.addEventListener('click', refreshDirectory);

  els.openAddRemoteBtn.addEventListener('click', openAddRemoteModal);
  els.closeAddRemoteBtn.addEventListener('click', closeAddRemoteModal);
  els.cancelAddRemoteBtn.addEventListener('click', closeAddRemoteModal);
  els.addRemoteForm.addEventListener('submit', submitAddRemote);

  els.providerTabs.querySelectorAll('.provider-tab').forEach((btn) => {
    btn.addEventListener('click', () => setRemoteProviderKind(btn.dataset.kind));
  });

  document.querySelectorAll('input[name="oauthAuthMode"]').forEach((r) => {
    r.addEventListener('change', updateOAuthAuthModeFields);
  });

  els.remotePolicySelect.addEventListener('change', () => {
    els.remotePrefixField.classList.toggle('hidden', els.remotePolicySelect.value !== 'targeted');
  });

  els.browseRemoteRootBtn.addEventListener('click', () => {
    openPicker({
      title: 'Select Local Encrypted Backend Folder',
      mode: 'folder',
      initialPath: els.remoteRootInput.value || null,
      confirmLabel: 'Use This Folder',
      onConfirm: (folder) => {
        els.remoteRootInput.value = folder;
      },
    });
  });

  document.querySelectorAll('input[name="policyMode"]').forEach((r) => {
    r.addEventListener('change', () => {
      state.routingDirty = true;
      updateRoutingEditorVisibility();
    });
  });

  els.targetedDefaultSelect.addEventListener('change', () => {
    state.routingDirty = true;
  });

  els.addPrefixRuleBtn.addEventListener('click', () => {
    state.routingDirty = true;
    appendTargetedRuleRow('/Docs', els.targetedDefaultSelect.value || '');
  });

  els.applyPolicyBtn.addEventListener('click', applyRoutingPolicy);

  els.mountPathInput.addEventListener('input', () => {
    state.mountPathDirty = true;
  });

  els.browseMountBtn.addEventListener('click', () => {
    openPicker({
      title: 'Choose Virtual Drive Mount Directory',
      mode: 'folder',
      initialPath: els.mountPathInput.value || null,
      confirmLabel: 'Use Mount Point',
      onConfirm: (folder) => {
        state.mountPathDirty = true;
        els.mountPathInput.value = folder;
      },
    });
  });

  els.mountDriveBtn.addEventListener('click', async () => {
    const mount_point = els.mountPathInput.value.trim();
    if (!mount_point) {
      showToast('Specify a mount point folder path', 'error');
      return;
    }
    try {
      els.mountDriveBtn.disabled = true;
      const msg = await invoke('mount_drive', {
        mount_point,
        use_mock_vfs: els.useMockVfsCheckbox.checked,
      });
      state.mountPathDirty = false;
      showToast(msg, 'ok');
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      await refreshStatus();
    }
  });

  els.unmountDriveBtn.addEventListener('click', async () => {
    try {
      els.unmountDriveBtn.disabled = true;
      const msg = await invoke('unmount_drive');
      showToast(msg, 'ok');
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      await refreshStatus();
    }
  });

  els.openMountFolderBtn.addEventListener('click', async () => {
    const path = els.mountPathInput.value.trim();
    try {
      const msg = await invoke('open_in_file_manager', { path });
      showToast(msg, 'ok');
    } catch (err) {
      showToast(String(err), 'error');
    }
  });

  els.runBenchBtn.addEventListener('click', async () => {
    const mib = Number.parseInt(els.benchSizeSelect.value || '64', 10) || 64;
    els.runBenchBtn.disabled = true;
    els.runBenchBtn.textContent = 'Running...';
    try {
      await executeBenchmark(mib, 'security');
    } finally {
      els.runBenchBtn.disabled = false;
      els.runBenchBtn.textContent = 'Run Benchmark';
    }
  });

  els.refreshConflictsBtn.addEventListener('click', refreshConflicts);

  els.closePickerBtn.addEventListener('click', closePicker);
  els.pickerCancelBtn.addEventListener('click', closePicker);
  els.pickerConfirmBtn.addEventListener('click', confirmPickerSelection);
  els.pickerUpBtn.addEventListener('click', () => {
    if (state.picker.parentPath) loadPickerDir(state.picker.parentPath);
  });
  els.pickerGoBtn.addEventListener('click', () => loadPickerDir(els.pickerPathInput.value.trim()));
  els.pickerPathInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      loadPickerDir(els.pickerPathInput.value.trim());
    }
  });
  els.pickerNewDirBtn.addEventListener('click', () => {
    els.pickerNewDirBar.classList.remove('hidden');
    els.pickerNewDirNameInput.value = '';
    els.pickerNewDirNameInput.focus();
  });
  els.pickerCreateDirCancelBtn.addEventListener('click', () => {
    els.pickerNewDirBar.classList.add('hidden');
  });
  els.pickerCreateDirConfirmBtn.addEventListener('click', async () => {
    const name = els.pickerNewDirNameInput.value.trim();
    if (!name) return;
    try {
      const created = await invoke('create_local_dir', {
        parent_path: state.picker.currentPath,
        name,
      });
      els.pickerNewDirBar.classList.add('hidden');
      await loadPickerDir(created);
    } catch (err) {
      showToast(String(err), 'error');
    }
  });

  els.closeDialogBtn.addEventListener('click', closeDialog);
  els.dialogCancelBtn.addEventListener('click', closeDialog);
  els.dialogForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const fn = state.dialogHandler;
    if (!fn) return;
    try {
      els.dialogConfirmBtn.disabled = true;
      await fn(els.dialogInput.value);
      closeDialog();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.dialogConfirmBtn.disabled = false;
    }
  });

  if (tauriEvent) {
    tauriEvent.listen('tauri://drag-enter', () => {
      if (state.status && state.status.unlocked && state.activeTab === 'files') {
        els.dropOverlay.classList.remove('hidden');
      }
    });
    tauriEvent.listen('tauri://drag-leave', () => {
      els.dropOverlay.classList.add('hidden');
    });
    tauriEvent.listen('tauri://drag-drop', async (event) => {
      els.dropOverlay.classList.add('hidden');
      if (!state.status || !state.status.unlocked) return;
      const payload = event.payload;
      const paths = Array.isArray(payload)
        ? payload
        : payload && Array.isArray(payload.paths)
          ? payload.paths
          : [];
      if (!paths.length) return;
      try {
        const msg = await invoke('import_local_files', {
          local_paths: paths,
          virtual_dir: state.currentVirtualDir,
        });
        showToast(msg, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      } catch (err) {
        showToast(String(err), 'error');
      }
    });
  }

  loadHardwareCaps();
  refreshStatus();
  setInterval(refreshStatus, 2000);
})();
