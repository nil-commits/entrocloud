'use strict';

(() => {
  const tauriCore =
    window.__TAURI__ && window.__TAURI__.core ? window.__TAURI__.core : null;
  const tauriEvent =
    window.__TAURI__ && window.__TAURI__.event ? window.__TAURI__.event : null;

  async function invoke(cmd, args) {
    if (!tauriCore) {
      throw new Error('Desktop IPC bridge unavailable');
    }
    return tauriCore.invoke(cmd, args || {});
  }

  const state = {
    status: null,
    activeTab: 'files',
    currentVirtualDir: '/',
    viewMode: 'grid',
    selectedVirtualPath: null,
    entries: [],
    conflicts: [],
    detectedClouds: [],
    hwCaps: null,
    selectedProviderKind: 'gdrive',
    lastAutoRemoteId: 'gdrive-1',
    mountPathDirty: false,
    routingDirty: false,
    routingRemoteSignature: '',
    dialogHandler: null,
    contextEntry: null,
    noteModal: {
      mode: 'new',
      virtualPath: null,
    },
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
    authHeading: document.getElementById('authHeading'),
    authSubtitle: document.getElementById('authSubtitle'),
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
    unlockPassInput: document.getElementById('unlockPassInput'),
    toggleUnlockPassBtn: document.getElementById('toggleUnlockPassBtn'),
    unlockSubmitBtn: document.getElementById('unlockSubmitBtn'),
    authQuitBtn: document.getElementById('authQuitBtn'),

    workspaceView: document.getElementById('workspaceView'),
    navDirtyBadge: document.getElementById('navDirtyBadge'),
    navRemoteBadge: document.getElementById('navRemoteBadge'),
    navMountDot: document.getElementById('navMountDot'),
    navConflictBadge: document.getElementById('navConflictBadge'),
    sidebarQuotaPct: document.getElementById('sidebarQuotaPct'),
    sidebarQuotaFill: document.getElementById('sidebarQuotaFill'),
    sidebarQuotaText: document.getElementById('sidebarQuotaText'),
    quitAppBtn: document.getElementById('quitAppBtn'),

    viewTitle: document.getElementById('viewTitle'),
    syncStatusPill: document.getElementById('syncStatusPill'),
    syncNowBtn: document.getElementById('syncNowBtn'),
    lockVaultBtn: document.getElementById('lockVaultBtn'),

    tabPanels: {
      files: document.getElementById('tab-files'),
      remotes: document.getElementById('tab-remotes'),
      mount: document.getElementById('tab-mount'),
      security: document.getElementById('tab-security'),
    },

    guidedCloudBanner: document.getElementById('guidedCloudBanner'),
    chooseOtherCloudFolderBtn: document.getElementById('chooseOtherCloudFolderBtn'),
    detectedCloudsBannerGrid: document.getElementById('detectedCloudsBannerGrid'),

    vaultUpBtn: document.getElementById('vaultUpBtn'),
    vaultBreadcrumbs: document.getElementById('vaultBreadcrumbs'),
    fileSearchInput: document.getElementById('fileSearchInput'),
    gridViewBtn: document.getElementById('gridViewBtn'),
    listViewBtn: document.getElementById('listViewBtn'),
    newFolderBtn: document.getElementById('newFolderBtn'),
    newNoteBtn: document.getElementById('newNoteBtn'),
    addFolderBtn: document.getElementById('addFolderBtn'),
    uploadFilesBtn: document.getElementById('uploadFilesBtn'),
    dropZone: document.getElementById('dropZone'),
    dropOverlay: document.getElementById('dropOverlay'),
    filesGrid: document.getElementById('filesGrid'),
    filesTableWrap: document.getElementById('filesTableWrap'),
    filesTableBody: document.getElementById('filesTableBody'),
    filesEmptyState: document.getElementById('filesEmptyState'),
    emptyUploadBtn: document.getElementById('emptyUploadBtn'),
    emptyNoteBtn: document.getElementById('emptyNoteBtn'),
    emptyFolderBtn: document.getElementById('emptyFolderBtn'),

    openAddRemoteBtn: document.getElementById('openAddRemoteBtn'),
    remotesGrid: document.getElementById('remotesGrid'),
    multiBackupCard: document.getElementById('multiBackupCard'),
    activePolicySummary: document.getElementById('activePolicySummary'),
    applyPolicyBtn: document.getElementById('applyPolicyBtn'),
    policyBackendsPicker: document.getElementById('policyBackendsPicker'),
    policyBackendsCheckboxes: document.getElementById('policyBackendsCheckboxes'),
    mirroredStrictRow: document.getElementById('mirroredStrictRow'),
    mirroredStrictCheckbox: document.getElementById('mirroredStrictCheckbox'),
    targetedConfigPane: document.getElementById('targetedConfigPane'),
    targetedDefaultSelect: document.getElementById('targetedDefaultSelect'),
    addPrefixRuleBtn: document.getElementById('addPrefixRuleBtn'),
    targetedRulesList: document.getElementById('targetedRulesList'),

    mountStatusPill: document.getElementById('mountStatusPill'),
    mountPathInput: document.getElementById('mountPathInput'),
    browseMountBtn: document.getElementById('browseMountBtn'),
    useMockVfsCheckbox: document.getElementById('useMockVfsCheckbox'),
    mountDriveBtn: document.getElementById('mountDriveBtn'),
    unmountDriveBtn: document.getElementById('unmountDriveBtn'),
    openMountFolderBtn: document.getElementById('openMountFolderBtn'),
    statBytesRead: document.getElementById('statBytesRead'),
    statBytesWritten: document.getElementById('statBytesWritten'),
    statRateSummary: document.getElementById('statRateSummary'),

    settingsLockBtn: document.getElementById('settingsLockBtn'),
    settingsQuitBtn: document.getElementById('settingsQuitBtn'),
    secBackendLabel: document.getElementById('secBackendLabel'),
    secCapsGrid: document.getElementById('secCapsGrid'),
    runBenchBtn: document.getElementById('runBenchBtn'),
    benchResultCard: document.getElementById('benchResultCard'),
    benchEncRate: document.getElementById('benchEncRate'),
    benchEncBar: document.getElementById('benchEncBar'),
    benchDecRate: document.getElementById('benchDecRate'),
    benchDecBar: document.getElementById('benchDecBar'),
    refreshConflictsBtn: document.getElementById('refreshConflictsBtn'),
    conflictsTableBody: document.getElementById('conflictsTableBody'),
    conflictsEmpty: document.getElementById('conflictsEmpty'),

    entryContextMenu: document.getElementById('entryContextMenu'),
    ctxOpenBtn: document.getElementById('ctxOpenBtn'),
    ctxOpenAppBtn: document.getElementById('ctxOpenAppBtn'),
    ctxExportBtn: document.getElementById('ctxExportBtn'),
    ctxSep1: document.getElementById('ctxSep1'),
    ctxOfflineBtn: document.getElementById('ctxOfflineBtn'),
    ctxFreeSpaceBtn: document.getElementById('ctxFreeSpaceBtn'),
    ctxRenameBtn: document.getElementById('ctxRenameBtn'),
    ctxDeleteBtn: document.getElementById('ctxDeleteBtn'),

    addRemoteModal: document.getElementById('addRemoteModal'),
    closeAddRemoteBtn: document.getElementById('closeAddRemoteBtn'),
    addTabFoldersBtn: document.getElementById('addTabFoldersBtn'),
    addTabServersBtn: document.getElementById('addTabServersBtn'),
    addFoldersPane: document.getElementById('addFoldersPane'),
    addServersPane: document.getElementById('addServersPane'),
    modalDetectedCloudsGrid: document.getElementById('modalDetectedCloudsGrid'),
    modalPickAnyFolderBtn: document.getElementById('modalPickAnyFolderBtn'),
    cancelAddRemoteBtn: document.getElementById('cancelAddRemoteBtn'),
    providerTabs: document.getElementById('providerTabs'),
    addRemoteForm: document.getElementById('addRemoteForm'),
    remoteIdInput: document.getElementById('remoteIdInput'),
    remoteRootLabel: document.getElementById('remoteRootLabel'),
    remoteRootInput: document.getElementById('remoteRootInput'),
    remoteQuotaGbInput: document.getElementById('remoteQuotaGbInput'),
    oauthFields: document.getElementById('oauthFields'),
    oauthPkceFields: document.getElementById('oauthPkceFields'),
    oauthTokenFields: document.getElementById('oauthTokenFields'),
    oauthClientIdInput: document.getElementById('oauthClientIdInput'),
    oauthClientSecretInput: document.getElementById('oauthClientSecretInput'),
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
    submitAddRemoteBtn: document.getElementById('submitAddRemoteBtn'),

    noteModal: document.getElementById('noteModal'),
    noteModalHeading: document.getElementById('noteModalHeading'),
    closeNoteModalBtn: document.getElementById('closeNoteModalBtn'),
    noteForm: document.getElementById('noteForm'),
    noteNameField: document.getElementById('noteNameField'),
    noteFileNameInput: document.getElementById('noteFileNameInput'),
    noteBodyInput: document.getElementById('noteBodyInput'),
    noteOpenDefaultBtn: document.getElementById('noteOpenDefaultBtn'),
    cancelNoteBtn: document.getElementById('cancelNoteBtn'),
    saveNoteBtn: document.getElementById('saveNoteBtn'),

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
    toast.className =
      'toast' + (kind === 'ok' ? ' ok' : kind === 'error' ? ' error' : '');
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

  function formatSizeHuman(bytes) {
    if (!bytes || bytes <= 0) return '0 B';
    const kb = 1024;
    const mb = kb * 1024;
    const gb = mb * 1024;
    const tb = gb * 1024;
    if (bytes < kb) return bytes + ' B';
    if (bytes < mb) return (bytes / kb).toFixed(1) + ' KB';
    if (bytes < gb) return (bytes / mb).toFixed(1) + ' MB';
    if (bytes < tb) return (bytes / gb).toFixed(2) + ' GB';
    return (bytes / tb).toFixed(2) + ' TB';
  }

  function formatIsoTimestamp(iso) {
    if (!iso) return '--';
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  function humanHydrationLabel(entry) {
    if (entry.is_dir) return 'Folder';
    if (entry.pinned) return 'Always Keep Offline';
    switch (entry.hydration) {
      case 'online-only':
        return 'Cloud Only (Saves Space)';
      case 'dirty':
        return 'Syncing...';
      case 'cached':
      case 'partially-hydrated':
      default:
        return 'Saved on PC';
    }
  }

  function hydrationBadgeClass(entry) {
    if (entry.is_dir) return 'pill';
    if (entry.pinned) return 'pill pill-ok';
    switch (entry.hydration) {
      case 'dirty':
        return 'pill pill-warn';
      case 'online-only':
        return 'pill';
      default:
        return 'pill pill-info';
    }
  }

  function isTextNoteFile(name) {
    return /\.(txt|md|markdown|json|csv|log|ini|yaml|yml|toml|conf)$/i.test(name || '');
  }

  function createEntrySvg(entry, small) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '1.8');
    svg.setAttribute(
      'class',
      'entry-svg' + (entry.is_dir ? '' : ' is-file') + (small ? ' entry-svg-sm' : '')
    );

    if (entry.is_dir) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute(
        'd',
        'M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'
      );
      svg.appendChild(path);
    } else {
      const page = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      page.setAttribute(
        'd',
        'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'
      );
      const fold = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
      fold.setAttribute('points', '14 2 14 8 20 8');
      svg.append(page, fold);
    }
    return svg;
  }

  function evaluatePasswordStrength(pass) {
    if (!pass) return { pct: 0, label: 'Enter password', color: 'var(--danger)' };
    let score = 0;
    if (pass.length >= 8) score += 20;
    if (pass.length >= 12) score += 25;
    if (pass.length >= 16) score += 15;
    if (/[a-z]/.test(pass) && /[A-Z]/.test(pass)) score += 15;
    if (/\d/.test(pass)) score += 10;
    if (/[^A-Za-z0-9]/.test(pass)) score += 15;
    const pct = Math.min(100, score);
    if (pct < 40) return { pct, label: 'Weak — try making it longer', color: 'var(--danger)' };
    if (pct < 70) return { pct, label: 'Good — a few more characters help', color: 'var(--warn)' };
    if (pct < 90) return { pct, label: 'Strong', color: 'var(--accent)' };
    return { pct, label: 'Excellent', color: 'var(--ok)' };
  }

  function updateStrengthMeter() {
    const p1 = els.initPassInput.value;
    const p2 = els.initPassConfirmInput.value;
    const s = evaluatePasswordStrength(p1);
    els.passStrengthFill.style.width = s.pct + '%';
    els.passStrengthFill.style.backgroundColor = s.color;
    els.passStrengthLabel.textContent = s.label;

    if (!p2) {
      els.passMatchHint.textContent = 'Keep this safe — it cannot be recovered if lost.';
      els.passMatchHint.className = 'tiny muted';
      els.passMatchHint.style.color = '';
    } else if (p1 === p2) {
      els.passMatchHint.textContent = 'Passwords match';
      els.passMatchHint.className = 'tiny';
      els.passMatchHint.style.color = 'var(--ok)';
    } else {
      els.passMatchHint.textContent = 'Passwords do not match yet';
      els.passMatchHint.className = 'tiny';
      els.passMatchHint.style.color = 'var(--danger)';
    }
  }

  async function loadDetectedClouds() {
    try {
      const clouds = await invoke('detect_installed_clouds');
      state.detectedClouds = clouds || [];
      renderDetectedClouds(els.detectedCloudsBannerGrid, true);
      renderDetectedClouds(els.modalDetectedCloudsGrid, false);
    } catch (_) {
      state.detectedClouds = [];
    }
  }

  function renderDetectedClouds(container, isBanner) {
    if (!container) return;
    container.replaceChildren();
    for (const cloud of state.detectedClouds) {
      const card = document.createElement('button');
      card.type = 'button';
      card.className = 'cloud-choice-card';

      const titleRow = document.createElement('div');
      titleRow.className = 'cloud-choice-title';
      const title = document.createElement('span');
      title.textContent = cloud.display_name;
      const pill = document.createElement('span');
      pill.className = 'pill pill-info';
      pill.textContent = cloud.provider_key === 'local' ? 'Ready Offline' : '1-Click Sync';
      titleRow.append(title, pill);

      const path = document.createElement('div');
      path.className = 'cloud-choice-path';
      path.textContent = cloud.suggested_vault_path;
      path.title = cloud.suggested_vault_path;

      const desc = document.createElement('div');
      desc.className = 'tiny muted';
      desc.textContent = cloud.description;

      card.append(titleRow, path, desc);
      card.addEventListener('click', () => connectOneClickCloud(cloud, isBanner, card));
      container.appendChild(card);
    }
  }

  async function connectOneClickCloud(cloud, fromBanner, cardEl) {
    try {
      if (cardEl) cardEl.disabled = true;
      await invoke('connect_folder_storage', {
        name: cloud.display_name,
        folder_path: cloud.suggested_vault_path,
      });
      showToast('Connected backup storage: ' + cloud.display_name, 'ok');
      if (!fromBanner) closeAddRemoteModal();
      state.routingDirty = false;
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      if (cardEl) cardEl.disabled = false;
    }
  }

  async function connectCustomFolderStorage(closeModalAfter) {
    const selected = await pickFolderSmart('Choose a synced folder, drive, or USB disk');
    if (!selected) return;
    const segs = selected.replace(/[\\/]+$/, '').split(/[\\/]/);
    const folderLabel = segs[segs.length - 1] || 'My Backup';
    try {
      await invoke('connect_folder_storage', {
        name: folderLabel,
        folder_path: selected,
      });
      showToast('Connected backup folder: ' + folderLabel, 'ok');
      if (closeModalAfter) closeAddRemoteModal();
      state.routingDirty = false;
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  async function loadHardwareCaps() {
    try {
      const caps = await invoke('get_hardware_caps');
      state.hwCaps = caps;
      els.secBackendLabel.textContent = caps.mandatory_satisfied
        ? 'Hardware encryption is built into your processor and active.'
        : 'Hardware encryption status check returned warnings.';

      const items = [
        { name: 'Hardware AES Acceleration', ok: caps.aes_hw },
        { name: 'Fast Integrity Tagging', ok: caps.pclmul_hw },
        { name: 'Vector Encryption', ok: caps.vaes_hw || caps.avx2_hw },
      ];
      els.secCapsGrid.replaceChildren();
      for (const item of items) {
        const card = document.createElement('div');
        card.className = 'cap-item';
        const label = document.createElement('span');
        label.textContent = item.name;
        const pill = document.createElement('span');
        pill.className = item.ok ? 'pill pill-ok' : 'pill';
        pill.textContent = item.ok ? 'Active' : 'Standard';
        card.append(label, pill);
        els.secCapsGrid.appendChild(card);
      }
    } catch (err) {
      els.secBackendLabel.textContent = String(err);
    }
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

      if (!vm.vault_initialized) {
        els.authHeading.textContent = 'Welcome to Zerovault';
        els.authSubtitle.textContent = 'Keep your personal files private across every cloud.';
        els.initVaultForm.classList.remove('hidden');
        els.unlockVaultForm.classList.add('hidden');
      } else {
        els.authHeading.textContent = 'Welcome Back';
        els.authSubtitle.textContent = 'Enter your Master Password to open your vault.';
        els.initVaultForm.classList.add('hidden');
        els.unlockVaultForm.classList.remove('hidden');
        setTimeout(() => {
          if (document.activeElement !== els.unlockPassInput) {
            els.unlockPassInput.focus();
          }
        }, 40);
      }
      return;
    }

    const justUnlocked = els.workspaceView.classList.contains('hidden');
    els.connectingView.classList.add('hidden');
    els.authView.classList.add('hidden');
    els.workspaceView.classList.remove('hidden');

    if (justUnlocked) {
      state.currentVirtualDir = '/';
      state.mountPathDirty = false;
      state.routingDirty = false;
      loadDetectedClouds();
      refreshDirectory();
      refreshConflicts();
    }
  }

  function friendlyPolicySummary(raw) {
    if (!raw) return 'Automatic';
    if (raw.QuotaPooled) return 'Combine Storage Space';
    if (raw.Mirrored) return 'Mirror Backup Copies';
    if (raw.Targeted) return 'Organize by Folder';
    return 'Automatic';
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

    const remotes = vm.remotes || [];
    if (vm.pending_dirty_ops > 0) {
      els.syncStatusPill.textContent = 'Syncing changes...';
      els.syncStatusPill.className = 'pill pill-warn';
      els.navDirtyBadge.textContent = String(vm.pending_dirty_ops);
      els.navDirtyBadge.classList.remove('hidden');
    } else if (remotes.length === 0) {
      els.syncStatusPill.textContent = 'Saved on This PC';
      els.syncStatusPill.className = 'pill pill-info';
      els.navDirtyBadge.classList.add('hidden');
    } else {
      els.syncStatusPill.textContent = 'All files protected & up to date';
      els.syncStatusPill.className = 'pill pill-ok';
      els.navDirtyBadge.classList.add('hidden');
    }

    if (remotes.length === 0) {
      els.sidebarQuotaPct.textContent = '--';
      els.sidebarQuotaFill.style.width = '0%';
      els.sidebarQuotaText.textContent = 'Choose a backup location to start';
    } else if (vm.quota_total_bytes > 0) {
      const pct = Math.min(100, Math.max(0, vm.quota_used_percent));
      els.sidebarQuotaPct.textContent = pct.toFixed(0) + '%';
      els.sidebarQuotaFill.style.width = pct.toFixed(1) + '%';
      els.sidebarQuotaText.textContent =
        formatSizeHuman(vm.quota_used_bytes) + ' of ' + formatSizeHuman(vm.quota_total_bytes);
    } else {
      els.sidebarQuotaPct.textContent = 'Ready';
      els.sidebarQuotaFill.style.width = '100%';
      els.sidebarQuotaText.textContent = formatSizeHuman(vm.quota_used_bytes) + ' backed up';
    }

    els.navRemoteBadge.textContent = String(remotes.length);
    els.navMountDot.classList.toggle('mounted', Boolean(vm.mounted));

    if (vm.conflict_count > 0) {
      els.navConflictBadge.textContent = String(vm.conflict_count);
      els.navConflictBadge.classList.remove('hidden');
    } else {
      els.navConflictBadge.classList.add('hidden');
    }

    els.guidedCloudBanner.classList.toggle('hidden', remotes.length > 0);

    renderRemotesGrid(remotes);
    els.multiBackupCard.classList.toggle('hidden', remotes.length < 2);
    els.activePolicySummary.textContent = friendlyPolicySummary(vm.routing_policy_raw);

    const sig = remotes.map((r) => r.id).join(',');
    if (!state.routingDirty || sig !== state.routingRemoteSignature) {
      state.routingRemoteSignature = sig;
      syncRoutingEditorFromStatus(vm);
    }

    // Computer Drive tab
    els.mountStatusPill.textContent = vm.mounted ? 'Active in Explorer' : 'Off';
    els.mountStatusPill.className = vm.mounted ? 'pill pill-ok' : 'pill';
    els.mountDriveBtn.disabled = vm.mounted;
    els.unmountDriveBtn.disabled = !vm.mounted;
    if (!state.mountPathDirty) {
      els.mountPathInput.value = vm.mount_point || vm.default_mount_point || '';
    }

    els.statBytesRead.textContent = vm.bytes_read_label;
    els.statBytesWritten.textContent = vm.bytes_written_label;
    const isBusy = vm.upload_bytes_per_sec > 0 || vm.download_bytes_per_sec > 0;
    els.statRateSummary.textContent = isBusy
      ? vm.upload_rate + ' up / ' + vm.download_rate + ' down'
      : 'Idle';
  }

  async function refreshStatus() {
    try {
      const vm = await invoke('fetch_status');
      renderStatus(vm);
    } catch (err) {
      renderStatus({ daemon_reachable: false, error_message: String(err) });
    }
  }

  function setActiveTab(tab) {
    state.activeTab = tab;
    const titles = {
      files: 'My Files',
      remotes: 'Cloud Backup',
      mount: 'Computer Drive',
      security: 'Settings',
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

  function parentVirtualDir(path) {
    if (!path || path === '/') return '/';
    const idx = path.lastIndexOf('/');
    return idx <= 0 ? '/' : path.slice(0, idx);
  }

  function renderBreadcrumbs() {
    els.vaultBreadcrumbs.replaceChildren();
    const inSub = state.currentVirtualDir !== '/';
    els.vaultUpBtn.classList.toggle('hidden', !inSub);

    const rootBtn = document.createElement('button');
    rootBtn.type = 'button';
    rootBtn.className = 'crumb-btn';
    rootBtn.textContent = 'My Files';
    rootBtn.addEventListener('click', () => navigateVaultDir('/'));
    els.vaultBreadcrumbs.appendChild(rootBtn);

    const parts = state.currentVirtualDir.split('/').filter(Boolean);
    let accum = '';
    for (const part of parts) {
      const sep = document.createElement('span');
      sep.className = 'crumb-sep';
      sep.textContent = '>';
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

  function renderDirectoryEntries() {
    renderBreadcrumbs();
    const q = (els.fileSearchInput.value || '').trim().toLowerCase();
    const filtered = q
      ? state.entries.filter((e) => e.name.toLowerCase().includes(q))
      : state.entries;

    els.filesGrid.replaceChildren();
    els.filesTableBody.replaceChildren();

    if (filtered.length === 0) {
      els.filesGrid.classList.add('hidden');
      els.filesTableWrap.classList.add('hidden');
      els.filesEmptyState.classList.remove('hidden');
      return;
    }

    els.filesEmptyState.classList.add('hidden');
    els.filesGrid.classList.toggle('hidden', state.viewMode !== 'grid');
    els.filesTableWrap.classList.toggle('hidden', state.viewMode !== 'list');

    if (state.viewMode === 'grid') {
      for (const entry of filtered) {
        const card = document.createElement('div');
        card.className =
          'file-tile' +
          (state.selectedVirtualPath === entry.virtual_path ? ' selected' : '');

        const top = document.createElement('div');
        top.className = 'file-tile-top';
        const icon = createEntrySvg(entry, false);
        const moreBtn = document.createElement('button');
        moreBtn.type = 'button';
        moreBtn.className = 'more-btn';
        moreBtn.textContent = '...';
        moreBtn.title = 'Options';
        moreBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          const rect = moreBtn.getBoundingClientRect();
          openContextMenu(entry, rect.left - 140, rect.bottom + 4);
        });
        top.append(icon, moreBtn);

        const name = document.createElement('div');
        name.className = 'file-tile-name';
        name.textContent = entry.name;
        name.title = entry.name;

        const meta = document.createElement('div');
        meta.className = 'file-tile-meta';
        const size = document.createElement('span');
        size.textContent = entry.is_dir ? 'Folder' : formatSizeHuman(entry.size);
        const status = document.createElement('span');
        status.className = hydrationBadgeClass(entry);
        status.textContent = humanHydrationLabel(entry);
        meta.append(size, status);

        card.append(top, name, meta);
        card.addEventListener('click', () => {
          state.selectedVirtualPath = entry.virtual_path;
          renderDirectoryEntries();
        });
        card.addEventListener('dblclick', () => openVaultEntrySmart(entry));
        card.addEventListener('contextmenu', (ev) => {
          ev.preventDefault();
          state.selectedVirtualPath = entry.virtual_path;
          openContextMenu(entry, ev.clientX, ev.clientY);
        });

        els.filesGrid.appendChild(card);
      }
    } else {
      for (const entry of filtered) {
        const tr = document.createElement('tr');
        if (state.selectedVirtualPath === entry.virtual_path) {
          tr.className = 'selected';
        }

        const nameTd = document.createElement('td');
        const nameBtn = document.createElement('button');
        nameBtn.type = 'button';
        nameBtn.className = 'entry-name-btn';
        const icon = createEntrySvg(entry, true);
        const label = document.createElement('span');
        label.textContent = entry.name;
        nameBtn.append(icon, label);
        nameBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          openVaultEntrySmart(entry);
        });
        nameTd.appendChild(nameBtn);

        const sizeTd = document.createElement('td');
        sizeTd.className = 'tiny muted';
        sizeTd.textContent = entry.is_dir ? '--' : formatSizeHuman(entry.size);

        const modTd = document.createElement('td');
        modTd.className = 'tiny muted';
        modTd.textContent = formatIsoTimestamp(entry.modified_at);

        const stateTd = document.createElement('td');
        const pill = document.createElement('span');
        pill.className = hydrationBadgeClass(entry);
        pill.textContent = humanHydrationLabel(entry);
        stateTd.appendChild(pill);

        const menuTd = document.createElement('td');
        menuTd.className = 'align-right';
        const moreBtn = document.createElement('button');
        moreBtn.type = 'button';
        moreBtn.className = 'more-btn';
        moreBtn.textContent = '...';
        moreBtn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          const rect = moreBtn.getBoundingClientRect();
          openContextMenu(entry, rect.left - 160, rect.bottom + 4);
        });
        menuTd.appendChild(moreBtn);

        tr.append(nameTd, sizeTd, modTd, stateTd, menuTd);
        tr.addEventListener('click', () => {
          state.selectedVirtualPath = entry.virtual_path;
          renderDirectoryEntries();
        });
        tr.addEventListener('dblclick', () => openVaultEntrySmart(entry));
        tr.addEventListener('contextmenu', (ev) => {
          ev.preventDefault();
          state.selectedVirtualPath = entry.virtual_path;
          openContextMenu(entry, ev.clientX, ev.clientY);
        });
        els.filesTableBody.appendChild(tr);
      }
    }
  }

  async function navigateVaultDir(virtualPath) {
    state.currentVirtualDir = virtualPath || '/';
    state.selectedVirtualPath = null;
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

  async function openVaultEntrySmart(entry) {
    if (entry.is_dir) {
      await navigateVaultDir(entry.virtual_path);
      return;
    }
    if (isTextNoteFile(entry.name) && entry.size <= 2 * 1024 * 1024) {
      await openExistingNote(entry);
      return;
    }
    await openFileInOsApp(entry);
  }

  async function openFileInOsApp(entry) {
    try {
      const msg = await invoke('open_vault_file', {
        virtual_path: entry.virtual_path,
      });
      showToast(msg, 'ok');
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  // Note Editor Modal
  async function openExistingNote(entry) {
    try {
      const note = await invoke('read_vault_text_file', {
        virtual_path: entry.virtual_path,
      });
      state.noteModal = { mode: 'edit', virtualPath: note.virtual_path };
      els.noteModalHeading.textContent = note.name;
      els.noteFileNameInput.value = note.name;
      els.noteNameField.classList.add('hidden');
      els.noteBodyInput.value = note.content;
      els.noteOpenDefaultBtn.classList.remove('hidden');
      els.noteModal.classList.remove('hidden');
      setTimeout(() => els.noteBodyInput.focus(), 40);
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  function openNewNoteModal() {
    state.noteModal = { mode: 'new', virtualPath: null };
    els.noteModalHeading.textContent = 'New Encrypted Note';
    els.noteNameField.classList.remove('hidden');
    els.noteFileNameInput.value = 'Quick Note.txt';
    els.noteBodyInput.value = '';
    els.noteOpenDefaultBtn.classList.add('hidden');
    els.noteModal.classList.remove('hidden');
    setTimeout(() => els.noteBodyInput.focus(), 40);
  }

  function closeNoteModal() {
    els.noteModal.classList.add('hidden');
    els.noteBodyInput.value = '';
  }

  // Context Menu
  function openContextMenu(entry, x, y) {
    state.contextEntry = entry;
    const isFile = !entry.is_dir;
    els.ctxOpenBtn.textContent = isFile && isTextNoteFile(entry.name) ? 'Edit Note' : 'Open';
    els.ctxOpenAppBtn.classList.toggle('hidden', !isFile);
    els.ctxExportBtn.classList.toggle('hidden', !isFile);
    els.ctxSep1.classList.toggle('hidden', !isFile);
    els.ctxOfflineBtn.classList.toggle('hidden', !isFile);
    els.ctxFreeSpaceBtn.classList.toggle('hidden', !isFile);

    if (isFile) {
      els.ctxOfflineBtn.textContent = entry.pinned
        ? '\u2713 Always Keep Offline (On)'
        : 'Always Keep Offline';
    }

    els.entryContextMenu.classList.remove('hidden');
    const maxX = Math.max(12, window.innerWidth - 230);
    const maxY = Math.max(12, window.innerHeight - 280);
    els.entryContextMenu.style.left = Math.min(x, maxX) + 'px';
    els.entryContextMenu.style.top = Math.min(y, maxY) + 'px';
  }

  function closeContextMenu() {
    els.entryContextMenu.classList.add('hidden');
    state.contextEntry = null;
  }

  // Native Dialog Helpers (fallback to in-app picker ONLY when OS dialog unavailable)
  async function pickFilesSmart() {
    const native = await invoke('pick_local_files_dialog');
    if (native !== null) return native;
    return new Promise((resolve) => {
      openFallbackPicker({
        title: 'Choose Files to Add',
        mode: 'files',
        confirmLabel: 'Add Selected Files',
        onConfirm: async (paths) => resolve(paths),
        onCancel: () => resolve([]),
      });
    });
  }

  async function pickFolderSmart(title) {
    const native = await invoke('pick_local_folder_dialog', { title });
    if (native !== null) return native;
    return new Promise((resolve) => {
      openFallbackPicker({
        title: title || 'Choose Folder',
        mode: 'folder',
        confirmLabel: 'Choose This Folder',
        onConfirm: async (folder) => resolve(folder),
        onCancel: () => resolve(null),
      });
    });
  }

  async function pickSaveDestinationSmart(entry) {
    const nativeSave = await invoke('pick_save_file_dialog', {
      suggested_name: entry.name,
    });
    if (nativeSave !== null) return nativeSave;
    return pickFolderSmart('Choose where to save "' + entry.name + '"');
  }

  async function addFilesFlow() {
    try {
      const paths = await pickFilesSmart();
      if (!paths || paths.length === 0) return;
      const msg = await invoke('import_local_files', {
        local_paths: paths,
        virtual_dir: state.currentVirtualDir,
      });
      showToast(msg, 'ok');
      await Promise.all([refreshDirectory(), refreshStatus()]);
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  async function addFolderFlow() {
    try {
      const folder = await pickFolderSmart('Choose a folder to add to your vault');
      if (!folder) return;
      const msg = await invoke('import_local_files', {
        local_paths: [folder],
        virtual_dir: state.currentVirtualDir,
      });
      showToast(msg, 'ok');
      await Promise.all([refreshDirectory(), refreshStatus()]);
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  async function saveCopyToComputer(entry) {
    try {
      const dest = await pickSaveDestinationSmart(entry);
      if (!dest) return;
      await invoke('export_vault_file', {
        virtual_path: entry.virtual_path,
        local_dest_path: dest,
      });
      showToast('Saved decrypted copy of ' + entry.name, 'ok');
    } catch (err) {
      showToast(String(err), 'error');
    }
  }

  function promptNewFolder() {
    openDialog({
      title: 'Create New Folder',
      message: 'New folder name inside ' + (state.currentVirtualDir === '/' ? 'My Files' : state.currentVirtualDir),
      inputLabel: 'Folder Name',
      inputValue: '',
      placeholder: 'e.g. Taxes & Receipts',
      confirmLabel: 'Create Folder',
      danger: false,
      onConfirm: async (name) => {
        const trimmed = name.trim();
        if (!trimmed) throw new Error('Folder name cannot be empty');
        const prefix = state.currentVirtualDir === '/' ? '' : state.currentVirtualDir;
        await invoke('create_vault_dir', { virtual_path: prefix + '/' + trimmed });
        showToast('Created folder ' + trimmed, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  function promptRenameEntry(entry) {
    openDialog({
      title: 'Rename',
      message: 'Enter a new name for "' + entry.name + '":',
      inputLabel: 'New Name',
      inputValue: entry.name,
      placeholder: entry.name,
      confirmLabel: 'Rename',
      danger: false,
      onConfirm: async (newName) => {
        const trimmed = newName.trim();
        if (!trimmed) throw new Error('Name cannot be empty');
        await invoke('rename_vault_entry', {
          virtual_path: entry.virtual_path,
          new_name_or_path: trimmed,
        });
        showToast('Renamed to ' + trimmed, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  function promptDeleteEntry(entry) {
    const desc = entry.is_dir
      ? 'Delete folder "' + entry.name + '" and everything inside it?'
      : 'Delete "' + entry.name + '" from your vault?';
    openDialog({
      title: 'Delete',
      message: desc,
      inputLabel: null,
      confirmLabel: 'Delete',
      danger: true,
      onConfirm: async () => {
        await invoke('delete_vault_entry', {
          virtual_path: entry.virtual_path,
          recursive: entry.is_dir,
        });
        showToast('Deleted ' + entry.name, 'ok');
        await Promise.all([refreshDirectory(), refreshStatus()]);
      },
    });
  }

  // Cloud Backup Grid & Multi-Backup Rules
  function renderRemotesGrid(remotes) {
    els.remotesGrid.replaceChildren();
    if (!remotes.length) {
      const card = document.createElement('div');
      card.className = 'panel-card';
      const p = document.createElement('p');
      p.className = 'muted';
      p.textContent =
        'No backup storage connected yet. Click "+ Add Backup Location" to connect OneDrive, Google Drive, Dropbox, a local folder, or a cloud server.';
      card.appendChild(p);
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
      const badge = document.createElement('span');
      badge.className = r.healthy ? 'pill pill-ok' : 'pill pill-warn';
      badge.textContent = r.healthy ? 'Connected' : 'Check Connection';
      titleWrap.append(dot, title, badge);

      const removeBtn = document.createElement('button');
      removeBtn.type = 'button';
      removeBtn.className = 'btn btn-sm btn-danger';
      removeBtn.textContent = 'Disconnect';
      removeBtn.addEventListener('click', () => {
        openDialog({
          title: 'Disconnect Storage',
          message:
            'Disconnect "' +
            r.id +
            '" from Zerovault? Your encrypted backup files inside that folder stay untouched.',
          inputLabel: null,
          confirmLabel: 'Disconnect',
          danger: true,
          onConfirm: async () => {
            await invoke('remove_remote', { id: r.id });
            state.routingDirty = false;
            showToast('Disconnected ' + r.id, 'ok');
            await refreshStatus();
          },
        });
      });
      head.append(titleWrap, removeBtn);

      const rootEl = document.createElement('div');
      rootEl.className = 'remote-path';
      rootEl.textContent = r.root;
      rootEl.title = r.root;

      const track = document.createElement('div');
      track.className = 'progress-track';
      const fill = document.createElement('div');
      fill.className = 'progress-fill';
      const pct =
        r.total_bytes > 0 ? Math.min(100, (r.used_bytes / r.total_bytes) * 100) : 0;
      fill.style.width = pct.toFixed(1) + '%';
      track.appendChild(fill);

      const quotaEl = document.createElement('div');
      quotaEl.className = 'tiny muted';
      quotaEl.textContent =
        r.total_bytes > 0
          ? formatSizeHuman(r.used_bytes) + ' used of ' + formatSizeHuman(r.total_bytes)
          : formatSizeHuman(r.used_bytes) + ' stored';

      card.append(head, rootEl, track, quotaEl);
      if (r.last_error) {
        const errEl = document.createElement('div');
        errEl.className = 'tiny';
        errEl.style.color = '#fecaca';
        errEl.textContent = r.last_error;
        card.appendChild(errEl);
      }
      els.remotesGrid.appendChild(card);
    }
  }

  function syncRoutingEditorFromStatus(vm) {
    const remotes = vm.remotes || [];
    const policy = vm.routing_policy_raw;
    let mode = 'pooled';
    let selectedBackends = remotes.map((r) => r.id);
    let strictAll = false;
    let defaultBackend = remotes[0] ? remotes[0].id : '';
    let rules = [];

    if (policy) {
      if (policy.QuotaPooled) {
        mode = 'pooled';
        selectedBackends = policy.QuotaPooled.pool_backends || selectedBackends;
      } else if (policy.Mirrored) {
        mode = 'mirrored';
        selectedBackends = policy.Mirrored.backends || selectedBackends;
        strictAll = (policy.Mirrored.min_ack || 1) >= selectedBackends.length;
      } else if (policy.Targeted) {
        mode = 'targeted';
        defaultBackend = policy.Targeted.default_backend || defaultBackend;
        rules = policy.Targeted.prefix_routes || [];
      }
    }

    const radio = document.querySelector('input[name="policyMode"][value="' + mode + '"]');
    if (radio) radio.checked = true;

    renderRoutingBackendChoices(remotes, selectedBackends, strictAll);
    renderTargetedEditor(remotes, defaultBackend, rules);
    updateRoutingEditorVisibility();
  }

  function renderRoutingBackendChoices(remotes, selectedIds, strictAll) {
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
      text.textContent = r.id;
      label.append(cb, text);
      els.policyBackendsCheckboxes.appendChild(label);
    }
    els.mirroredStrictCheckbox.checked = Boolean(strictAll);
  }

  function renderTargetedEditor(remotes, defaultBackend, rules) {
    els.targetedDefaultSelect.replaceChildren();
    for (const r of remotes) {
      const opt = document.createElement('option');
      opt.value = r.id;
      opt.textContent = r.id;
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
    els.mirroredStrictRow.classList.toggle('hidden', mode !== 'mirrored');
    els.targetedConfigPane.classList.toggle('hidden', mode !== 'targeted');
  }

  async function applyRoutingPolicy() {
    const modeRadio = document.querySelector('input[name="policyMode"]:checked');
    const mode = modeRadio ? modeRadio.value : 'pooled';

    const checkedBackends = Array.from(
      document.querySelectorAll('input[name="policyBackendCheck"]:checked')
    ).map((el) => el.value);

    const minAck = els.mirroredStrictCheckbox.checked
      ? Math.max(1, checkedBackends.length)
      : Math.max(1, Math.floor(checkedBackends.length / 2) + 1);

    const rules = Array.from(els.targetedRulesList.querySelectorAll('.rule-row')).map(
      (row) => {
        const pfx = row.querySelector('input').value.trim();
        const bk = row.querySelector('select').value;
        return [pfx, bk];
      }
    );

    try {
      els.applyPolicyBtn.disabled = true;
      await invoke('set_routing_policy', {
        input: {
          mode,
          backends: checkedBackends,
          min_ack: minAck,
          default_backend: els.targetedDefaultSelect.value || null,
          prefix_routes: rules,
        },
      });
      state.routingDirty = false;
      showToast('Backup preferences updated', 'ok');
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.applyPolicyBtn.disabled = false;
    }
  }

  // Add Storage Modal
  const SERVER_DEFAULTS = {
    gdrive: { id: 'gdrive-1', root: '/zerovault', label: 'Google Drive Folder' },
    onedrive: { id: 'onedrive-1', root: '/zerovault', label: 'OneDrive Folder' },
    dropbox: { id: 'dropbox-1', root: '/zerovault', label: 'Dropbox Folder' },
    s3: { id: 's3-main', root: 'zerovault', label: 'Folder Prefix Inside Bucket' },
    webdav: { id: 'webdav-1', root: '/zerovault', label: 'Server Subfolder' },
  };

  function setServerProviderKind(kind) {
    const prev = SERVER_DEFAULTS[state.selectedProviderKind];
    state.selectedProviderKind = kind;
    const def = SERVER_DEFAULTS[kind] || SERVER_DEFAULTS.gdrive;

    document.querySelectorAll('.provider-tab').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.kind === kind);
    });

    if (!els.remoteIdInput.value.trim() || els.remoteIdInput.value === state.lastAutoRemoteId) {
      els.remoteIdInput.value = def.id;
      state.lastAutoRemoteId = def.id;
    }
    if (!els.remoteRootInput.value.trim() || (prev && els.remoteRootInput.value === prev.root)) {
      els.remoteRootInput.value = def.root;
    }
    els.remoteRootLabel.textContent = def.label;

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
    loadDetectedClouds();
    els.addRemoteForm.reset();
    els.remoteIdInput.value = '';
    els.remoteRootInput.value = '';
    els.remoteQuotaGbInput.value = '';
    document.querySelectorAll('.gb-preset').forEach((b) => {
      b.classList.toggle('active', b.dataset.gb === '');
    });
    setServerProviderKind('gdrive');
    updateOAuthAuthModeFields();
    switchAddModalTab('folders');
    els.addRemoteModal.classList.remove('hidden');
  }

  function switchAddModalTab(which) {
    els.addTabFoldersBtn.classList.toggle('active', which === 'folders');
    els.addTabServersBtn.classList.toggle('active', which === 'servers');
    els.addFoldersPane.classList.toggle('hidden', which !== 'folders');
    els.addServersPane.classList.toggle('hidden', which !== 'servers');
  }

  function closeAddRemoteModal() {
    els.addRemoteModal.classList.add('hidden');
  }

  async function submitAddRemote(ev) {
    ev.preventDefault();
    const kind = state.selectedProviderKind;
    const id = els.remoteIdInput.value.trim();
    const root = els.remoteRootInput.value.trim();
    const gbRaw = els.remoteQuotaGbInput.value.trim();
    const quota_mib = gbRaw && Number.parseFloat(gbRaw) > 0
      ? Math.round(Number.parseFloat(gbRaw) * 1024)
      : null;

    if (!id || !root) {
      showToast('Backup Name and Remote Folder are required', 'error');
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
          throw new Error('Enter your App Client ID to sign in');
        }
        els.submitAddRemoteBtn.textContent = 'Waiting for Browser Sign-In...';
        showToast('Browser opened — finish signing in to connect...', 'info');
        await invoke('oauth_login_remote', {
          params: {
            id,
            kind,
            root,
            client_id,
            client_secret: els.oauthClientSecretInput.value || null,
            auth_url: null,
            token_url: null,
            quota_mib,
            policy: 'pooled',
            prefix: null,
          },
        });
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
          if (!bucket) throw new Error('Enter your S3 Bucket Name');
        } else if (kind === 'webdav') {
          endpoint = els.davEndpointInput.value.trim() || null;
          username = els.davUserInput.value.trim() || null;
          secret = els.davPassInput.value || null;
          if (!endpoint) throw new Error('Enter your WebDAV Server URL');
        } else if (isOAuth) {
          username = els.oauthClientIdInput.value.trim() || null;
          secret = els.oauthRawTokenInput.value.trim() || null;
          if (!secret) throw new Error('Paste your access token or token JSON');
        }

        await invoke('add_remote', {
          params: {
            id,
            kind,
            root,
            endpoint,
            bucket,
            region,
            quota_mib,
            policy: 'pooled',
            prefix: null,
            username,
            secret,
          },
        });
      }

      showToast('Connected ' + id, 'ok');
      closeAddRemoteModal();
      state.routingDirty = false;
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.submitAddRemoteBtn.disabled = false;
      els.submitAddRemoteBtn.textContent = 'Connect Storage';
    }
  }

  // Conflicts & Speed Test
  async function refreshConflicts() {
    if (!state.status || !state.status.unlocked) return;
    try {
      const list = await invoke('list_conflicts');
      state.conflicts = list || [];
      renderConflicts();
    } catch (_) {
      state.conflicts = [];
      renderConflicts();
    }
  }

  function renderConflicts() {
    els.conflictsTableBody.replaceChildren();
    els.conflictsEmpty.classList.toggle('hidden', state.conflicts.length > 0);
    for (const c of state.conflicts) {
      const tr = document.createElement('tr');
      const tdOrig = document.createElement('td');
      tdOrig.textContent = c.original_path;
      const tdCopy = document.createElement('td');
      tdCopy.textContent = c.conflict_path;
      const tdTime = document.createElement('td');
      tdTime.className = 'tiny muted';
      tdTime.textContent = formatIsoTimestamp(c.detected_at);
      tr.append(tdOrig, tdCopy, tdTime);
      els.conflictsTableBody.appendChild(tr);
    }
  }

  function formatSpeedHuman(mibPerSec) {
    if (mibPerSec >= 1024) {
      return (mibPerSec / 1024).toFixed(2) + ' GB/s';
    }
    return mibPerSec.toFixed(0) + ' MB/s';
  }

  async function executeSpeedTest() {
    try {
      els.runBenchBtn.disabled = true;
      els.runBenchBtn.textContent = 'Testing...';
      const report = await invoke('run_crypto_benchmark', { mib: 64 });
      els.benchResultCard.classList.remove('hidden');
      els.benchEncRate.textContent = formatSpeedHuman(report.encrypt_mib_per_sec);
      els.benchDecRate.textContent = formatSpeedHuman(report.decrypt_mib_per_sec);
      const maxRate = Math.max(report.encrypt_mib_per_sec, report.decrypt_mib_per_sec, 1000);
      els.benchEncBar.style.width =
        Math.min(100, (report.encrypt_mib_per_sec / maxRate) * 100).toFixed(1) + '%';
      els.benchDecBar.style.width =
        Math.min(100, (report.decrypt_mib_per_sec / maxRate) * 100).toFixed(1) + '%';
      showToast(
        'Speed test finished: ' + formatSpeedHuman(report.decrypt_mib_per_sec) + ' read',
        'ok'
      );
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.runBenchBtn.disabled = false;
      els.runBenchBtn.textContent = 'Test Vault Speed';
    }
  }

  // Fallback Picker Modal (only when native OS dialogs are absent)
  function openFallbackPicker(opts) {
    state.picker.mode = opts.mode || 'folder';
    state.picker.includeFiles = opts.mode === 'files';
    state.picker.selectedFiles = new Set();
    state.picker.onConfirm = opts.onConfirm;
    state.picker.onCancel = opts.onCancel;
    els.pickerTitle.textContent = opts.title || 'Select Path';
    els.pickerConfirmBtn.textContent = opts.confirmLabel || 'Select';
    els.pickerNewDirBar.classList.add('hidden');
    els.pickerModal.classList.remove('hidden');
    loadPickerDir(opts.initialPath || null);
  }

  function closePicker(cancelled) {
    els.pickerModal.classList.add('hidden');
    const cancelFn = state.picker.onCancel;
    state.picker.onConfirm = null;
    state.picker.onCancel = null;
    if (cancelled && cancelFn) cancelFn();
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
        btn.addEventListener('click', () => loadPickerDir(root.path));
        els.pickerQuickRoots.appendChild(btn);
      }

      els.pickerEntries.replaceChildren();
      for (const item of listing.entries || []) {
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

        const icon = createEntrySvg({ is_dir: item.is_dir }, true);
        const name = document.createElement('span');
        name.className = 'picker-row-name';
        name.textContent = item.name;
        const size = document.createElement('span');
        size.className = 'tiny muted';
        size.textContent = item.is_dir ? 'Folder' : formatSizeHuman(item.size);
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
      els.pickerSelectionLabel.textContent = state.picker.currentPath;
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
    state.picker.onCancel = null;
    closePicker(false);
    await fn(payload);
  }

  // Generic Dialog Modal
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
      showAuthError('Enter a Master Password first');
      return;
    }
    if (pass !== confirm) {
      showAuthError('Both passwords must match');
      return;
    }
    try {
      els.initSubmitBtn.disabled = true;
      els.initSubmitBtn.textContent = 'Creating Your Vault...';
      await invoke('init_vault', { passphrase: pass });
      els.initPassInput.value = '';
      els.initPassConfirmInput.value = '';
      showToast('Your private vault is ready!', 'ok');
      await refreshStatus();
    } catch (err) {
      showAuthError(String(err));
    } finally {
      els.initSubmitBtn.disabled = false;
      els.initSubmitBtn.textContent = 'Create My Vault';
    }
  });

  els.unlockVaultForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    showAuthError('');
    const pass = els.unlockPassInput.value;
    if (!pass) {
      showAuthError('Enter your Master Password');
      return;
    }
    try {
      els.unlockSubmitBtn.disabled = true;
      els.unlockSubmitBtn.textContent = 'Unlocking...';
      await invoke('unlock_vault', { passphrase: pass });
      els.unlockPassInput.value = '';
      await refreshStatus();
    } catch (err) {
      const txt = String(err);
      showAuthError(
        txt.includes('invalid_passphrase')
          ? 'That Master Password did not match. Please try again.'
          : txt
      );
    } finally {
      els.unlockSubmitBtn.disabled = false;
      els.unlockSubmitBtn.textContent = 'Unlock My Vault';
    }
  });

  els.authQuitBtn.addEventListener('click', () => invoke('quit_app'));
  els.quitAppBtn.addEventListener('click', () => invoke('quit_app'));
  els.settingsQuitBtn.addEventListener('click', () => invoke('quit_app'));

  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.addEventListener('click', () => setActiveTab(btn.dataset.tab));
  });

  els.syncNowBtn.addEventListener('click', async () => {
    try {
      els.syncNowBtn.disabled = true;
      await invoke('sync_now');
      showToast('Everything is synced and backed up', 'ok');
      await Promise.all([refreshStatus(), refreshDirectory(), refreshConflicts()]);
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.syncNowBtn.disabled = false;
    }
  });

  async function doLockVault() {
    try {
      els.lockVaultBtn.disabled = true;
      els.settingsLockBtn.disabled = true;
      await invoke('lock_vault');
      showToast('Vault locked', 'ok');
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.lockVaultBtn.disabled = false;
      els.settingsLockBtn.disabled = false;
    }
  }
  els.lockVaultBtn.addEventListener('click', doLockVault);
  els.settingsLockBtn.addEventListener('click', doLockVault);

  // My Files Toolbar
  els.chooseOtherCloudFolderBtn.addEventListener('click', () =>
    connectCustomFolderStorage(false)
  );
  els.vaultUpBtn.addEventListener('click', () =>
    navigateVaultDir(parentVirtualDir(state.currentVirtualDir))
  );
  els.fileSearchInput.addEventListener('input', renderDirectoryEntries);
  els.gridViewBtn.addEventListener('click', () => {
    state.viewMode = 'grid';
    els.gridViewBtn.classList.add('active');
    els.listViewBtn.classList.remove('active');
    renderDirectoryEntries();
  });
  els.listViewBtn.addEventListener('click', () => {
    state.viewMode = 'list';
    els.listViewBtn.classList.add('active');
    els.gridViewBtn.classList.remove('active');
    renderDirectoryEntries();
  });

  els.newFolderBtn.addEventListener('click', promptNewFolder);
  els.emptyFolderBtn.addEventListener('click', promptNewFolder);
  els.newNoteBtn.addEventListener('click', openNewNoteModal);
  els.emptyNoteBtn.addEventListener('click', openNewNoteModal);
  els.uploadFilesBtn.addEventListener('click', addFilesFlow);
  els.emptyUploadBtn.addEventListener('click', addFilesFlow);
  els.addFolderBtn.addEventListener('click', addFolderFlow);

  // Context Menu Listeners
  document.addEventListener('click', (ev) => {
    if (!els.entryContextMenu.contains(ev.target)) {
      closeContextMenu();
    }
  });
  window.addEventListener('blur', closeContextMenu);

  els.ctxOpenBtn.addEventListener('click', () => {
    const entry = state.contextEntry;
    closeContextMenu();
    if (entry) openVaultEntrySmart(entry);
  });
  els.ctxOpenAppBtn.addEventListener('click', () => {
    const entry = state.contextEntry;
    closeContextMenu();
    if (entry) openFileInOsApp(entry);
  });
  els.ctxExportBtn.addEventListener('click', () => {
    const entry = state.contextEntry;
    closeContextMenu();
    if (entry) saveCopyToComputer(entry);
  });
  els.ctxOfflineBtn.addEventListener('click', async () => {
    const entry = state.contextEntry;
    closeContextMenu();
    if (!entry) return;
    try {
      if (entry.pinned) {
        await invoke('unpin_vault_entry', { virtual_path: entry.virtual_path });
        showToast('Removed offline pin from ' + entry.name, 'ok');
      } else {
        await invoke('pin_vault_entry', { virtual_path: entry.virtual_path });
        showToast(entry.name + ' will stay offline on this PC', 'ok');
      }
      await Promise.all([refreshDirectory(), refreshStatus()]);
    } catch (err) {
      showToast(String(err), 'error');
    }
  });
  els.ctxFreeSpaceBtn.addEventListener('click', async () => {
    const entry = state.contextEntry;
    closeContextMenu();
    if (!entry) return;
    try {
      await invoke('free_up_space', { virtual_path: entry.virtual_path });
      showToast('Freed local space — ' + entry.name + ' remains safely in your cloud', 'ok');
      await Promise.all([refreshDirectory(), refreshStatus()]);
    } catch (err) {
      showToast(String(err), 'error');
    }
  });
  els.ctxRenameBtn.addEventListener('click', () => {
    const entry = state.contextEntry;
    closeContextMenu();
    if (entry) promptRenameEntry(entry);
  });
  els.ctxDeleteBtn.addEventListener('click', () => {
    const entry = state.contextEntry;
    closeContextMenu();
    if (entry) promptDeleteEntry(entry);
  });

  // Note Modal Listeners
  els.closeNoteModalBtn.addEventListener('click', closeNoteModal);
  els.cancelNoteBtn.addEventListener('click', closeNoteModal);
  els.noteOpenDefaultBtn.addEventListener('click', async () => {
    const vpath = state.noteModal.virtualPath;
    closeNoteModal();
    if (vpath) {
      try {
        await invoke('open_vault_file', { virtual_path: vpath });
      } catch (err) {
        showToast(String(err), 'error');
      }
    }
  });
  els.noteForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    let targetPath = state.noteModal.virtualPath;
    if (state.noteModal.mode === 'new') {
      const name = els.noteFileNameInput.value.trim();
      if (!name || name.includes('/') || name.includes('\\')) {
        showToast('Enter a valid note file name', 'error');
        return;
      }
      const prefix = state.currentVirtualDir === '/' ? '' : state.currentVirtualDir;
      targetPath = prefix + '/' + name;
    }
    try {
      els.saveNoteBtn.disabled = true;
      els.saveNoteBtn.textContent = 'Saving...';
      const msg = await invoke('save_vault_text_file', {
        virtual_path: targetPath,
        content: els.noteBodyInput.value,
      });
      closeNoteModal();
      showToast(msg, 'ok');
      await Promise.all([refreshDirectory(), refreshStatus()]);
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      els.saveNoteBtn.disabled = false;
      els.saveNoteBtn.textContent = 'Save Encrypted Note';
    }
  });

  // Add Backup Location Modal Listeners
  els.openAddRemoteBtn.addEventListener('click', openAddRemoteModal);
  els.closeAddRemoteBtn.addEventListener('click', closeAddRemoteModal);
  els.cancelAddRemoteBtn.addEventListener('click', closeAddRemoteModal);
  els.addTabFoldersBtn.addEventListener('click', () => switchAddModalTab('folders'));
  els.addTabServersBtn.addEventListener('click', () => switchAddModalTab('servers'));
  els.modalPickAnyFolderBtn.addEventListener('click', () =>
    connectCustomFolderStorage(true)
  );
  els.addRemoteForm.addEventListener('submit', submitAddRemote);

  els.providerTabs.querySelectorAll('.provider-tab').forEach((btn) => {
    btn.addEventListener('click', () => setServerProviderKind(btn.dataset.kind));
  });
  document.querySelectorAll('.gb-preset').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.gb-preset').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      els.remoteQuotaGbInput.value = btn.dataset.gb || '';
    });
  });
  els.remoteQuotaGbInput.addEventListener('input', () => {
    document.querySelectorAll('.gb-preset').forEach((b) => b.classList.remove('active'));
  });
  document.querySelectorAll('input[name="oauthAuthMode"]').forEach((r) => {
    r.addEventListener('change', updateOAuthAuthModeFields);
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
  els.mirroredStrictCheckbox.addEventListener('change', () => {
    state.routingDirty = true;
  });
  els.addPrefixRuleBtn.addEventListener('click', () => {
    state.routingDirty = true;
    appendTargetedRuleRow('/Photos', els.targetedDefaultSelect.value || '');
  });
  els.applyPolicyBtn.addEventListener('click', applyRoutingPolicy);

  // Computer Drive Listeners
  els.mountPathInput.addEventListener('input', () => {
    state.mountPathDirty = true;
  });
  els.browseMountBtn.addEventListener('click', async () => {
    const folder = await pickFolderSmart('Choose Explorer folder for Zerovault');
    if (folder) {
      state.mountPathDirty = true;
      els.mountPathInput.value = folder;
    }
  });
  els.mountDriveBtn.addEventListener('click', async () => {
    const mount_point = els.mountPathInput.value.trim();
    if (!mount_point) {
      showToast('Choose a folder location on this PC first', 'error');
      return;
    }
    try {
      els.mountDriveBtn.disabled = true;
      await invoke('mount_drive', {
        mount_point,
        use_mock_vfs: els.useMockVfsCheckbox.checked,
      });
      state.mountPathDirty = false;
      showToast('Explorer folder turned on', 'ok');
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
      await invoke('unmount_drive');
      showToast('Explorer folder turned off', 'ok');
      await refreshStatus();
    } catch (err) {
      showToast(String(err), 'error');
    } finally {
      await refreshStatus();
    }
  });
  els.openMountFolderBtn.addEventListener('click', async () => {
    try {
      await invoke('open_in_file_manager', {
        path: els.mountPathInput.value.trim(),
      });
    } catch (err) {
      showToast(String(err), 'error');
    }
  });

  // Settings Listeners
  els.runBenchBtn.addEventListener('click', executeSpeedTest);
  els.refreshConflictsBtn.addEventListener('click', refreshConflicts);

  // Fallback Picker Listeners
  els.closePickerBtn.addEventListener('click', () => closePicker(true));
  els.pickerCancelBtn.addEventListener('click', () => closePicker(true));
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

  // Generic Dialog Listeners
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
