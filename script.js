/**
 * KEYBOX - Offline-First Password Manager & Private Vault
 * 
 * SECURITY ARCHITECTURE:
 * - All sensitive data encrypted with AES-256-GCM via Web Crypto API
 * - Key derived from user PIN using PBKDF2 (100,000 iterations)
 * - Unique random IV/nonce for every encryption operation
 * - Authentication tag provided by AES-GCM for integrity
 * - No plaintext sensitive data stored anywhere
 * - No external dependencies, APIs, or network requests
 * 
 * WARNING: Client-side JavaScript cannot be made impossible to inspect.
 * This application is designed to protect data at rest, not against
 * a determined attacker with full access to the device.
 */

'use strict';

/* ============================================
   CONSTANTS & CONFIGURATION
   ============================================ */

const APP_VERSION = '1.0.0';
const DB_NAME = 'keybox-vault';
const DB_VERSION = 1;
const ENCRYPTION_ALGORITHM = 'AES-GCM';
const ENCRYPTION_KEY_LENGTH = 256;
const PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const MAX_IMAGE_SIZE = 2 * 1024 * 1024; // 2MB
const ALLOWED_IMAGE_TYPES = ['image/png', 'image/jpeg', 'image/webp'];
const MAX_IMAGE_DIMENSION = 512;
const CLIPBOARD_TIMEOUT_DEFAULT = 30; // seconds
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 30000; // 30 seconds
const AUTO_LOCK_DEFAULT = '300'; // 5 minutes

/* ============================================
   STATE
   ============================================ */

const state = {
    db: null,
    cryptoKey: null,
    isUnlocked: false,
    currentScreen: 'home',
    currentSection: 'all',
    searchQuery: '',
    failedAttempts: 0,
    lockoutUntil: 0,
    autoLockTimer: null,
    clipboardTimer: null,
    settings: {
        pinEnabled: false,
        autoLock: AUTO_LOCK_DEFAULT,
        theme: 'system',
        language: 'en',
        clipboardTimeout: CLIPBOARD_TIMEOUT_DEFAULT
    },
    categories: [
        { id: 'social', name: 'Social' },
        { id: 'gaming', name: 'Gaming' },
        { id: 'work', name: 'Work' },
        { id: 'websites', name: 'Websites' },
        { id: 'other', name: 'Other' }
    ],
    editingItem: null,
    generatedPassword: '',
    pendingAction: null
};

/* ============================================
   I18N
   ============================================ */

const translations = {
    en: {
        app_name: 'KEYBOX',
        tagline: 'Your private box',
        home: 'Home',
        search: 'Search',
        add: 'Add',
        favorites: 'Favorites',
        settings: 'Settings',
        all: 'All',
        passwords: 'Passwords',
        notes: 'Notes',
        websites: 'Websites',
        password: 'Password',
        note: 'Note',
        website: 'Website',
        add_new: 'Add New',
        no_items: 'No items found',
        no_favorites: 'No favorites yet',
        security: 'Security',
        appearance: 'Appearance',
        about: 'About',
        pin_protection: 'PIN Protection',
        auto_lock: 'Auto Lock',
        clipboard_timeout: 'Clipboard Clear',
        create_backup: 'Create Backup',
        restore_backup: 'Restore Backup',
        delete_all_data: 'Delete All Data',
        theme: 'Theme',
        language: 'Language',
        system: 'System',
        light: 'Light',
        dark: 'Dark',
        off: 'Off',
        disabled: 'Disabled',
        enabled: 'Enabled',
        '15_seconds': '15 seconds',
        '30_seconds': '30 seconds',
        '1_minute': '1 minute',
        '5_minutes': '5 minutes',
        '10_minutes': '10 minutes',
        password_generator: 'Password Generator',
        generate: 'Generate',
        copy: 'Copy',
        use_password: 'Use Password',
        name: 'Name',
        username: 'Username / Email',
        link: 'Link',
        category: 'Category',
        notes: 'Notes',
        created: 'Created',
        updated: 'Updated',
        save: 'Save',
        cancel: 'Cancel',
        delete: 'Delete',
        edit: 'Edit',
        confirm_delete: 'Are you sure you want to delete this item?',
        confirm_delete_all: 'Are you sure you want to delete ALL data? This cannot be undone.',
        confirm_delete_all_final: 'Type DELETE to confirm permanent deletion',
        unable_to_unlock: 'Unable to unlock the vault.',
        wrong_pin: 'Incorrect PIN. Please try again.',
        too_many_attempts: 'Too many failed attempts. Please wait.',
        copied: 'Copied to clipboard',
        copy_failed: 'Failed to copy',
        password_copied: 'Password copied',
        username_copied: 'Username copied',
        link_copied: 'Link copied',
        backup_created: 'Backup created successfully',
        backup_restored: 'Backup restored successfully',
        backup_failed: 'Backup operation failed',
        invalid_backup: 'Invalid backup file',
        image_too_large: 'Image is too large (max 2MB)',
        image_invalid_type: 'Invalid image type',
        url_invalid: 'Invalid URL',
        required_field: 'This field is required',
        enter_pin: 'Enter your PIN to unlock KEYBOX',
        create_pin: 'Create a PIN',
        confirm_pin: 'Confirm PIN',
        pin_mismatch: 'PINs do not match',
        pin_created: 'PIN created successfully',
        pin_removed: 'PIN removed',
        pin_changed: 'PIN changed successfully',
        forgot_pin: 'Forgot PIN?',
        forgot_pin_message: 'If you forget your PIN, your data cannot be recovered. The only option is to delete all data and start over.',
        delete_all_and_reset: 'Delete All Data & Reset',
        opening_website: 'Opening website. Internet connection required.',
        cannot_open_url: 'Cannot open this URL safely.'
    },
    ar: {
        app_name: 'KEYBOX',
        tagline: 'صندوقك الخاص',
        home: 'الرئيسية',
        search: 'بحث',
        add: 'إضافة',
        favorites: 'المفضلة',
        settings: 'الإعدادات',
        all: 'الكل',
        passwords: 'كلمات المرور',
        notes: 'ملاحظات',
        websites: 'مواقع',
        password: 'كلمة مرور',
        note: 'ملاحظة',
        website: 'موقع',
        add_new: 'إضافة جديد',
        no_items: 'لا توجد عناصر',
        no_favorites: 'لا توجد مفضلات',
        security: 'الأمان',
        appearance: 'المظهر',
        about: 'حول',
        pin_protection: 'حماية PIN',
        auto_lock: 'القفل التلقائي',
        clipboard_timeout: 'مسح الحافظة',
        create_backup: 'إنشاء نسخة احتياطية',
        restore_backup: 'استعادة نسخة احتياطية',
        delete_all_data: 'حذف جميع البيانات',
        theme: 'السمة',
        language: 'اللغة',
        system: 'النظام',
        light: 'فاتح',
        dark: 'داكن',
        off: 'إيقاف',
        disabled: 'معطل',
        enabled: 'مفعل',
        '15_seconds': '15 ثانية',
        '30_seconds': '30 ثانية',
        '1_minute': 'دقيقة واحدة',
        '5_minutes': '5 دقائق',
        '10_minutes': '10 دقائق',
        password_generator: 'مولد كلمات المرور',
        generate: 'توليد',
        copy: 'نسخ',
        use_password: 'استخدام كلمة المرور',
        name: 'الاسم',
        username: 'اسم المستخدم / البريد',
        link: 'الرابط',
        category: 'الفئة',
        notes: 'ملاحظات',
        created: 'أنشئ',
        updated: 'حدث',
        save: 'حفظ',
        cancel: 'إلغاء',
        delete: 'حذف',
        edit: 'تعديل',
        confirm_delete: 'هل أنت متأكد من حذف هذا العنصر؟',
        confirm_delete_all: 'هل أنت متأكد من حذف جميع البيانات؟ لا يمكن التراجع.',
        confirm_delete_all_final: 'اكتب DELETE للتأكيد',
        unable_to_unlock: 'غير قادر على فتح الخزنة.',
        wrong_pin: 'رمز PIN غير صحيح. حاول مرة أخرى.',
        too_many_attempts: 'محاولات فاشلة كثيرة. يرجى الانتظار.',
        copied: 'تم النسخ',
        copy_failed: 'فشل النسخ',
        password_copied: 'تم نسخ كلمة المرور',
        username_copied: 'تم نسخ اسم المستخدم',
        link_copied: 'تم نسخ الرابط',
        backup_created: 'تم إنشاء النسخة الاحتياطية',
        backup_restored: 'تمت استعادة النسخة الاحتياطية',
        backup_failed: 'فشلت عملية النسخ الاحتياطي',
        invalid_backup: 'ملف نسخ احتياطي غير صالح',
        image_too_large: 'الصورة كبيرة جداً (الحد الأقصى 2MB)',
        image_invalid_type: 'نوع صورة غير صالح',
        url_invalid: 'رابط غير صالح',
        required_field: 'هذا الحقل مطلوب',
        enter_pin: 'أدخل رمز PIN لفتح KEYBOX',
        create_pin: 'إنشاء رمز PIN',
        confirm_pin: 'تأكيد رمز PIN',
        pin_mismatch: 'رموز PIN غير متطابقة',
        pin_created: 'تم إنشاء رمز PIN',
        pin_removed: 'تم إزالة رمز PIN',
        pin_changed: 'تم تغيير رمز PIN',
        forgot_pin: 'نسيت رمز PIN؟',
        forgot_pin_message: 'إذا نسيت رمز PIN، لا يمكن استعادة بياناتك. الخيار الوحيد هو حذف جميع البيانات والبدء من جديد.',
        delete_all_and_reset: 'حذف جميع البيانات وإعادة التعيين',
        opening_website: 'فتح الموقع. يتطلب اتصال بالإنترنت.',
        cannot_open_url: 'لا يمكن فتح هذا الرابط بأمان.'
    }
};

let currentLang = 'en';

function t(key) {
    return translations[currentLang]?.[key] || translations.en[key] || key;
}

/* ============================================
   DOM REFERENCES
   ============================================ */

const dom = {};

function cacheDomElements() {
    dom.appContainer = document.getElementById('app-container');
    dom.header = document.getElementById('app-header');
    dom.btnLock = document.getElementById('btn-lock');
    dom.mainContent = document.getElementById('main-content');
    
    // Screens
    dom.lockScreen = document.getElementById('lock-screen');
    dom.homeScreen = document.getElementById('home-screen');
    dom.addScreen = document.getElementById('add-screen');
    dom.formScreen = document.getElementById('form-screen');
    dom.favoritesScreen = document.getElementById('favorites-screen');
    dom.settingsScreen = document.getElementById('settings-screen');
    dom.detailScreen = document.getElementById('detail-screen');
    dom.generatorScreen = document.getElementById('generator-screen');
    
    // Lock Screen
    dom.pinDots = document.getElementById('pin-dots');
    dom.pinInput = document.getElementById('pin-input');
    dom.pinKeypad = document.getElementById('pin-keypad');
    dom.lockMessage = document.getElementById('lock-message');
    dom.btnForgotPin = document.getElementById('btn-forgot-pin');
    
    // Home Screen
    dom.searchInput = document.getElementById('search-input');
    dom.btnClearSearch = document.getElementById('btn-clear-search');
    dom.quickStats = document.getElementById('quick-stats');
    dom.statPasswords = document.getElementById('stat-passwords');
    dom.statNotes = document.getElementById('stat-notes');
    dom.statWebsites = document.getElementById('stat-websites');
    dom.sectionTabs = document.getElementById('section-tabs');
    dom.itemsList = document.getElementById('items-list');
    dom.emptyState = document.getElementById('empty-state');
    dom.emptyStateText = document.getElementById('empty-state-text');
    
    // Add Screen
    dom.btnAddPassword = document.getElementById('btn-add-password');
    dom.btnAddNote = document.getElementById('btn-add-note');
    dom.btnAddWebsite = document.getElementById('btn-add-website');
    
    // Form Screen
    dom.formTitle = document.getElementById('form-title');
    dom.itemForm = document.getElementById('item-form');
    
    // Favorites Screen
    dom.favoritesList = document.getElementById('favorites-list');
    dom.favoritesEmpty = document.getElementById('favorites-empty');
    
    // Settings Screen
    dom.btnTogglePin = document.getElementById('btn-toggle-pin');
    dom.pinStatusText = document.getElementById('pin-status-text');
    dom.autoLockSelect = document.getElementById('auto-lock-select');
    dom.clipboardTimeoutSelect = document.getElementById('clipboard-timeout-select');
    dom.btnBackup = document.getElementById('btn-backup');
    dom.btnRestore = document.getElementById('btn-restore');
    dom.btnDeleteAll = document.getElementById('btn-delete-all');
    dom.themeSelect = document.getElementById('theme-select');
    dom.languageSelect = document.getElementById('language-select');
    
    // Detail Screen
    dom.detailTitle = document.getElementById('detail-title');
    dom.detailContent = document.getElementById('detail-content');
    
    // Generator Screen
    dom.generatedPassword = document.getElementById('generated-password');
    dom.btnCopyGenerated = document.getElementById('btn-copy-generated');
    dom.genLength = document.getElementById('gen-length');
    dom.genLengthValue = document.getElementById('gen-length-value');
    dom.genUppercase = document.getElementById('gen-uppercase');
    dom.genLowercase = document.getElementById('gen-lowercase');
    dom.genNumbers = document.getElementById('gen-numbers');
    dom.genSymbols = document.getElementById('gen-symbols');
    dom.btnGenerate = document.getElementById('btn-generate');
    dom.btnUsePassword = document.getElementById('btn-use-password');
    
    // Navigation
    dom.bottomNav = document.getElementById('bottom-nav');
    dom.navBtns = document.querySelectorAll('.nav-btn');
    
    // Toast & Modal
    dom.toastContainer = document.getElementById('toast-container');
    dom.modalContainer = document.getElementById('modal-container');
    dom.modalContent = document.getElementById('modal-content');
    
    // File Inputs
    dom.restoreFileInput = document.getElementById('restore-file-input');
    dom.imageFileInput = document.getElementById('image-file-input');
    
    // Pin Input (hidden)
    dom.pinInputHidden = document.getElementById('pin-input');
}

/* ============================================
   DATABASE (IndexedDB)
   ============================================ */

function openDatabase() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            
            // Vault store - stores encrypted data
            if (!db.objectStoreNames.contains('vault')) {
                const vaultStore = db.createObjectStore('vault', { keyPath: 'id' });
                vaultStore.createIndex('type', 'type', { unique: false });
                vaultStore.createIndex('category', 'category', { unique: false });
                vaultStore.createIndex('favorite', 'favorite', { unique: false });
                vaultStore.createIndex('createdAt', 'createdAt', { unique: false });
                vaultStore.createIndex('updatedAt', 'updatedAt', { unique: false });
            }
            
            // Settings store - non-sensitive settings
            if (!db.objectStoreNames.contains('settings')) {
                db.createObjectStore('settings', { keyPath: 'key' });
            }
            
            // Categories store
            if (!db.objectStoreNames.contains('categories')) {
                db.createObjectStore('categories', { keyPath: 'id' });
            }
            
            // Metadata store - for encryption metadata (salt, IV for settings)
            if (!db.objectStoreNames.contains('metadata')) {
                db.createObjectStore('metadata', { keyPath: 'key' });
            }
        };
        
        request.onsuccess = (event) => {
            resolve(event.target.result);
        };
        
        request.onerror = (event) => {
            reject(event.target.error);
        };
    });
}

async function dbGet(storeName, key) {
    return new Promise((resolve, reject) => {
        const transaction = state.db.transaction(storeName, 'readonly');
        const store = transaction.objectStore(storeName);
        const request = store.get(key);
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function dbGetAll(storeName) {
    return new Promise((resolve, reject) => {
        const transaction = state.db.transaction(storeName, 'readonly');
        const store = transaction.objectStore(storeName);
        const request = store.getAll();
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function dbPut(storeName, value) {
    return new Promise((resolve, reject) => {
        const transaction = state.db.transaction(storeName, 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.put(value);
        
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

async function dbDelete(storeName, key) {
    return new Promise((resolve, reject) => {
        const transaction = state.db.transaction(storeName, 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.delete(key);
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

async function dbClear(storeName) {
    return new Promise((resolve, reject) => {
        const transaction = state.db.transaction(storeName, 'readwrite');
        const store = transaction.objectStore(storeName);
        const request = store.clear();
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

/* ============================================
   CRYPTOGRAPHY
   ============================================ */

/**
 * Generate a cryptographically secure random value
 */
function generateRandomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
}

/**
 * Generate a random salt for PBKDF2
 */
function generateSalt() {
    return generateRandomBytes(SALT_LENGTH);
}

/**
 * Generate a random IV for AES-GCM
 */
function generateIV() {
    return generateRandomBytes(IV_LENGTH);
}

/**
 * Convert ArrayBuffer to Base64 string
 */
function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 */
function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Convert string to ArrayBuffer
 */
function stringToBuffer(str) {
    return new TextEncoder().encode(str).buffer;
}

/**
 * Convert ArrayBuffer to string
 */
function bufferToString(buffer) {
    return new TextDecoder().decode(new Uint8Array(buffer));
}

/**
 * Derive encryption key from PIN using PBKDF2
 */
async function deriveKeyFromPin(pin, salt) {
    const pinBuffer = stringToBuffer(pin);
    
    const importedKey = await crypto.subtle.importKey(
        'raw',
        pinBuffer,
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    const derivedKey = await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: 'SHA-256'
        },
        importedKey,
        {
            name: ENCRYPTION_ALGORITHM,
            length: ENCRYPTION_KEY_LENGTH
        },
        false,
        ['encrypt', 'decrypt']
    );
    
    return derivedKey;
}

/**
 * Generate a random encryption key (for no-PIN mode)
 */
async function generateEncryptionKey() {
    return await crypto.subtle.generateKey(
        {
            name: ENCRYPTION_ALGORITHM,
            length: ENCRYPTION_KEY_LENGTH
        },
        true,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt data using AES-GCM
 */
async function encryptData(data, key) {
    const iv = generateIV();
    const dataBuffer = stringToBuffer(JSON.stringify(data));
    
    const encryptedBuffer = await crypto.subtle.encrypt(
        {
            name: ENCRYPTION_ALGORITHM,
            iv: iv
        },
        key,
        dataBuffer
    );
    
    return {
        iv: bufferToBase64(iv.buffer),
        data: bufferToBase64(encryptedBuffer)
    };
}

/**
 * Decrypt data using AES-GCM
 */
async function decryptData(encryptedData, key) {
    const ivBuffer = base64ToBuffer(encryptedData.iv);
    const dataBuffer = base64ToBuffer(encryptedData.data);
    
    const decryptedBuffer = await crypto.subtle.decrypt(
        {
            name: ENCRYPTION_ALGORITHM,
            iv: new Uint8Array(ivBuffer)
        },
        key,
        new Uint8Array(dataBuffer)
    );
    
    const decryptedString = bufferToString(decryptedBuffer);
    return JSON.parse(decryptedString);
}

/**
 * Encrypt a vault item for storage
 */
async function encryptVaultItem(item, key) {
    const encrypted = await encryptData(item, key);
    return {
        id: item.id,
        type: item.type,
        encrypted: encrypted,
        category: item.category || 'other',
        favorite: item.favorite || false,
        createdAt: item.createdAt,
        updatedAt: item.updatedAt
    };
}

/**
 * Decrypt a vault item
 */
async function decryptVaultItem(storedItem, key) {
    const decrypted = await decryptData(storedItem.encrypted, key);
    return {
        ...decrypted,
        id: storedItem.id,
        type: storedItem.type,
        category: storedItem.category,
        favorite: storedItem.favorite,
        createdAt: storedItem.createdAt,
        updatedAt: storedItem.updatedAt
    };
}

/* ============================================
   AUTHENTICATION & SESSION MANAGEMENT
   ============================================ */

async function initAuth() {
    // Check if PIN is configured
    const pinConfig = await dbGet('metadata', 'pin_config');
    
    if (pinConfig && pinConfig.enabled) {
        state.settings.pinEnabled = true;
        await showLockScreen();
    } else {
        // No PIN - generate or load encryption key
        const keyData = await dbGet('metadata', 'encryption_key');
        
        if (keyData && keyData.key) {
            // Import existing key
            state.cryptoKey = await importRawKey(keyData.key);
        } else {
            // Generate new key
            state.cryptoKey = await generateEncryptionKey();
            const exportedKey = await crypto.subtle.exportKey('raw', state.cryptoKey);
            await dbPut('metadata', {
                key: 'encryption_key',
                keyData: bufferToBase64(exportedKey)
            });
        }
        
        state.isUnlocked = true;
        await showScreen('home');
    }
}

async function importRawKey(keyData) {
    const keyBuffer = base64ToBuffer(keyData);
    return await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: ENCRYPTION_ALGORITHM, length: ENCRYPTION_KEY_LENGTH },
        true,
        ['encrypt', 'decrypt']
    );
}

async function showLockScreen() {
    state.isUnlocked = false;
    state.cryptoKey = null;
    resetPinInput();
    updatePinDots();
    await showScreen('lock');
    document.getElementById('pin-input').focus();
}

async function handlePinSubmit(pin) {
    if (state.lockoutUntil > Date.now()) {
        const waitSeconds = Math.ceil((state.lockoutUntil - Date.now()) / 1000);
        updateLockMessage(t('too_many_attempts') + ` (${waitSeconds}s)`);
        return;
    }
    
    const pinConfig = await dbGet('metadata', 'pin_config');
    
    if (!pinConfig) {
        updateLockMessage(t('unable_to_unlock'));
        return;
    }
    
    try {
        const salt = base64ToBuffer(pinConfig.salt);
        const key = await deriveKeyFromPin(pin, new Uint8Array(salt));
        
        // Verify by decrypting a test value
        const testData = await decryptData(pinConfig.verifyData, key);
        
        if (testData && testData.valid === true) {
            // Success
            state.cryptoKey = key;
            state.isUnlocked = true;
            state.failedAttempts = 0;
            state.lockoutUntil = 0;
            resetPinInput();
            updatePinDots();
            await showScreen('home');
        } else {
            handleFailedAttempt();
        }
    } catch (error) {
        handleFailedAttempt();
    }
}

function handleFailedAttempt() {
    state.failedAttempts++;
    
    if (state.failedAttempts >= MAX_FAILED_ATTEMPTS) {
        state.lockoutUntil = Date.now() + LOCKOUT_DURATION;
        state.failedAttempts = 0;
        updateLockMessage(t('too_many_attempts'));
    } else {
        updateLockMessage(t('wrong_pin'));
    }
    
    resetPinInput();
    updatePinDots();
}

async function setupPin(newPin) {
    const salt = generateSalt();
    const key = await deriveKeyFromPin(newPin, salt);
    
    // Create verification data
    const verifyData = await encryptData({ valid: true }, key);
    
    await dbPut('metadata', {
        key: 'pin_config',
        enabled: true,
        salt: bufferToBase64(salt.buffer),
        verifyData: verifyData
    });
    
    state.settings.pinEnabled = true;
    state.cryptoKey = key;
    state.isUnlocked = true;
    updatePinStatusUI();
}

async function removePin() {
    await dbDelete('metadata', 'pin_config');
    state.settings.pinEnabled = false;
    
    // Ensure we have an encryption key for no-PIN mode
    if (!state.cryptoKey) {
        state.cryptoKey = await generateEncryptionKey();
        const exportedKey = await crypto.subtle.exportKey('raw', state.cryptoKey);
        await dbPut('metadata', {
            key: 'encryption_key',
            keyData: bufferToBase64(exportedKey)
        });
    }
    
    updatePinStatusUI();
}

async function changePin(oldPin, newPin) {
    const pinConfig = await dbGet('metadata', 'pin_config');
    
    if (!pinConfig) return false;
    
    try {
        const salt = base64ToBuffer(pinConfig.salt);
        const key = await deriveKeyFromPin(oldPin, new Uint8Array(salt));
        const testData = await decryptData(pinConfig.verifyData, key);
        
        if (testData && testData.valid === true) {
            await setupPin(newPin);
            return true;
        }
    } catch (error) {
        // Invalid old PIN
    }
    
    return false;
}

function resetPinInput() {
    if (dom.pinInput) {
        dom.pinInput.value = '';
    }
}

function updatePinDots() {
    const pinLength = dom.pinInput ? dom.pinInput.value.length : 0;
    const dots = document.querySelectorAll('.pin-dot');
    dots.forEach((dot, index) => {
        if (index < pinLength) {
            dot.classList.add('filled');
        } else {
            dot.classList.remove('filled');
        }
    });
}

function updateLockMessage(message) {
    if (dom.lockMessage) {
        dom.lockMessage.textContent = message;
    }
}

/* ============================================
   SCREEN MANAGEMENT
   ============================================ */

async function showScreen(screenName) {
    const screens = ['lock', 'home', 'add', 'form', 'favorites', 'settings', 'detail', 'generator'];
    
    screens.forEach(name => {
        const screen = document.getElementById(`${name}-screen`);
        if (screen) {
            if (name === screenName) {
                screen.classList.add('active');
            } else {
                screen.classList.remove('active');
            }
        }
    });
    
    state.currentScreen = screenName;
    
    // Update navigation
    const navMap = {
        'home': 'home',
        'add': 'add',
        'favorites': 'favorites',
        'settings': 'settings'
    };
    
    const activeNav = navMap[screenName];
    if (activeNav) {
        dom.navBtns.forEach(btn => {
            if (btn.dataset.nav === activeNav) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });
    }
    
    // Screen-specific actions
    if (screenName === 'home') {
        await loadHomeData();
        resetAutoLockTimer();
    } else if (screenName === 'favorites') {
        await loadFavorites();
    } else if (screenName === 'settings') {
        loadSettingsUI();
    }
}

async function loadHomeData() {
    await loadCategories();
    await loadItems();
    await updateStats();
}

async function updateStats() {
    const items = await dbGetAll('vault');
    let passwordCount = 0;
    let noteCount = 0;
    let websiteCount = 0;
    
    for (const item of items) {
        try {
            const decrypted = await decryptVaultItem(item, state.cryptoKey);
            if (decrypted.type === 'password') passwordCount++;
            else if (decrypted.type === 'note') noteCount++;
            else if (decrypted.type === 'website') websiteCount++;
        } catch (error) {
            // Skip corrupted items
        }
    }
    
    dom.statPasswords.textContent = passwordCount;
    dom.statNotes.textContent = noteCount;
    dom.statWebsites.textContent = websiteCount;
}

async function loadItems() {
    const items = await dbGetAll('vault');
    const decryptedItems = [];
    
    for (const item of items) {
        try {
            const decrypted = await decryptVaultItem(item, state.cryptoKey);
            
            // Apply section filter
            if (state.currentSection === 'passwords' && decrypted.type !== 'password') continue;
            if (state.currentSection === 'notes' && decrypted.type !== 'note') continue;
            if (state.currentSection === 'websites' && decrypted.type !== 'website') continue;
            if (state.currentSection === 'favorites' && !decrypted.favorite) continue;
            
            // Apply search filter
            if (state.searchQuery) {
                const searchable = [
                    decrypted.name || '',
                    decrypted.username || '',
                    decrypted.email || '',
                    decrypted.link || '',
                    decrypted.notes || '',
                    decrypted.category || ''
                ].join(' ').toLowerCase();
                
                if (!searchable.includes(state.searchQuery.toLowerCase())) continue;
            }
            
            decryptedItems.push(decrypted);
        } catch (error) {
            // Skip corrupted items
        }
    }
    
    // Sort by updatedAt descending
    decryptedItems.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    
    renderItems(decryptedItems);
}

function renderItems(items) {
    if (!dom.itemsList) return;
    
    dom.itemsList.innerHTML = '';
    
    if (items.length === 0) {
        dom.emptyState.classList.remove('hidden');
        dom.emptyStateText.textContent = state.searchQuery ? t('no_items') : t('no_items');
        return;
    }
    
    dom.emptyState.classList.add('hidden');
    
    items.forEach(item => {
        const card = createItemCard(item);
        dom.itemsList.appendChild(card);
    });
}

function createItemCard(item) {
    const card = document.createElement('div');
    card.className = 'item-card';
    card.dataset.id = item.id;
    
    // Header
    const header = document.createElement('div');
    header.className = 'item-card-header';
    
    // Icon
    const iconDiv = document.createElement('div');
    iconDiv.className = 'item-icon';
    
    if (item.imageData) {
        const img = document.createElement('img');
        img.src = item.imageData;
        img.alt = '';
        iconDiv.appendChild(img);
    } else {
        iconDiv.innerHTML = getItemIcon(item.type);
    }
    
    // Info
    const infoDiv = document.createElement('div');
    infoDiv.className = 'item-info';
    
    const nameSpan = document.createElement('span');
    nameSpan.className = 'item-name';
    nameSpan.textContent = item.name || 'Untitled';
    
    const subtitleSpan = document.createElement('span');
    subtitleSpan.className = 'item-subtitle';
    
    if (item.type === 'password') {
        subtitleSpan.textContent = item.username || item.email || '••••••••';
    } else if (item.type === 'note') {
        subtitleSpan.textContent = (item.content || '').substring(0, 50) || 'No content';
    } else if (item.type === 'website') {
        subtitleSpan.textContent = item.link || 'No link';
    }
    
    infoDiv.appendChild(nameSpan);
    infoDiv.appendChild(subtitleSpan);
    
    // Actions
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'item-actions';
    
    // Favorite button
    const favBtn = document.createElement('button');
    favBtn.className = 'item-action-btn' + (item.favorite ? ' favorite' : '');
    favBtn.setAttribute('aria-label', 'Toggle favorite');
    favBtn.innerHTML = getFavoriteIcon(item.favorite);
    favBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        toggleFavorite(item.id);
    });
    
    actionsDiv.appendChild(favBtn);
    
    header.appendChild(iconDiv);
    header.appendChild(infoDiv);
    header.appendChild(actionsDiv);
    
    card.appendChild(header);
    
    // Category badge
    if (item.category && item.category !== 'other') {
        const categoryBadge = document.createElement('span');
        categoryBadge.className = 'item-category';
        const category = state.categories.find(c => c.id === item.category);
        categoryBadge.textContent = category ? category.name : item.category;
        card.appendChild(categoryBadge);
    }
    
    // Click handler
    card.addEventListener('click', () => {
        openDetail(item);
    });
    
    return card;
}

function getItemIcon(type) {
    if (type === 'password') {
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>`;
    } else if (type === 'note') {
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`;
    } else {
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>`;
    }
}

function getFavoriteIcon(isFavorite) {
    if (isFavorite) {
        return `<svg viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 00-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 00-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 000-7.78z"/></svg>`;
    } else {
        return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20.84 4.61a5.5 5.5 0 00-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 00-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 000-7.78z"/></svg>`;
    }
}

async function toggleFavorite(itemId) {
    const storedItem = await dbGet('vault', itemId);
    if (!storedItem) return;
    
    try {
        const decrypted = await decryptVaultItem(storedItem, state.cryptoKey);
        decrypted.favorite = !decrypted.favorite;
        decrypted.updatedAt = Date.now();
        
        const encrypted = await encryptVaultItem(decrypted, state.cryptoKey);
        await dbPut('vault', encrypted);
        
        await loadItems();
    } catch (error) {
        showToast(t('backup_failed'), 'error');
    }
}

async function loadFavorites() {
    if (!dom.favoritesList) return;
    
    const items = await dbGetAll('vault');
    const favorites = [];
    
    for (const item of items) {
        try {
            const decrypted = await decryptVaultItem(item, state.cryptoKey);
            if (decrypted.favorite) {
                favorites.push(decrypted);
            }
        } catch (error) {
            // Skip
        }
    }
    
    favorites.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
    
    dom.favoritesList.innerHTML = '';
    
    if (favorites.length === 0) {
        dom.favoritesEmpty.classList.remove('hidden');
        return;
    }
    
    dom.favoritesEmpty.classList.add('hidden');
    
    favorites.forEach(item => {
        const card = createItemCard(item);
        dom.favoritesList.appendChild(card);
    });
}

async function loadCategories() {
    const categories = await dbGetAll('categories');
    if (categories && categories.length > 0) {
        state.categories = categories;
    } else {
        // Initialize default categories
        const defaultCategories = [
            { id: 'social', name: 'Social' },
            { id: 'gaming', name: 'Gaming' },
            { id: 'work', name: 'Work' },
            { id: 'websites', name: 'Websites' },
            { id: 'other', name: 'Other' }
        ];
        
        for (const cat of defaultCategories) {
            await dbPut('categories', cat);
        }
        state.categories = defaultCategories;
    }
}

/* ============================================
   DETAIL VIEW
   ============================================ */

async function openDetail(item) {
    state.editingItem = item;
    dom.detailTitle.textContent = item.name || 'Details';
    
    const content = dom.detailContent;
    content.innerHTML = '';
    
    // Image
    if (item.imageData) {
        const imageRow = document.createElement('div');
        imageRow.className = 'detail-row';
        const img = document.createElement('img');
        img.src = item.imageData;
        img.alt = item.name || '';
        img.style.maxWidth = '100%';
        img.style.borderRadius = '8px';
        imageRow.appendChild(img);
        content.appendChild(imageRow);
    }
    
    // Password type specific
    if (item.type === 'password') {
        if (item.username || item.email) {
            addDetailRow(content, 'Username', item.username || item.email, () => {
                copyToClipboard(item.username || item.email);
                showToast(t('username_copied'), 'success');
            });
        }
        
        if (item.password) {
            addDetailRow(content, 'Password', '••••••••••', () => {
                copyToClipboard(item.password);
                showToast(t('password_copied'), 'success');
            }, true, item.password);
        }
        
        if (item.link) {
            addDetailRow(content, 'Link', item.link, () => {
                copyToClipboard(item.link);
                showToast(t('link_copied'), 'success');
            });
        }
    }
    
    // Note type specific
    if (item.type === 'note' && item.content) {
        const noteRow = document.createElement('div');
        noteRow.className = 'detail-row';
        const noteContent = document.createElement('div');
        noteContent.className = 'detail-value';
        noteContent.textContent = item.content;
        noteContent.style.whiteSpace = 'pre-wrap';
        noteContent.style.overflow = 'auto';
        noteRow.appendChild(noteContent);
        content.appendChild(noteRow);
    }
    
    // Website type specific
    if (item.type === 'website' && item.link) {
        addDetailRow(content, 'URL', item.link, () => {
            copyToClipboard(item.link);
            showToast(t('link_copied'), 'success');
        });
    }
    
    // Category
    if (item.category) {
        const category = state.categories.find(c => c.id === item.category);
        addDetailRow(content, 'Category', category ? category.name : item.category);
    }
    
    // Notes
    if (item.notes && item.type !== 'note') {
        addDetailRow(content, 'Notes', item.notes);
    }
    
    // Dates
    if (item.createdAt) {
        addDetailRow(content, 'Created', new Date(item.createdAt).toLocaleDateString());
    }
    if (item.updatedAt) {
        addDetailRow(content, 'Updated', new Date(item.updatedAt).toLocaleDateString());
    }
    
    // Action buttons
    const actionsRow = document.createElement('div');
    actionsRow.className = 'detail-row';
    actionsRow.style.justifyContent = 'flex-end';
    actionsRow.style.gap = '8px';
    
    // Edit button
    const editBtn = document.createElement('button');
    editBtn.className = 'btn-secondary';
    editBtn.textContent = t('edit');
    editBtn.style.flex = '0 0 auto';
    editBtn.style.padding = '10px 16px';
    editBtn.addEventListener('click', () => {
        openEditForm(item);
    });
    actionsRow.appendChild(editBtn);
    
    // Delete button
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'btn-danger';
    deleteBtn.textContent = t('delete');
    deleteBtn.style.flex = '0 0 auto';
    deleteBtn.style.padding = '10px 16px';
    deleteBtn.addEventListener('click', () => {
        confirmDeleteItem(item);
    });
    actionsRow.appendChild(deleteBtn);
    
    content.appendChild(actionsRow);
    
    // Website open button
    if (item.type === 'website' && item.link) {
        const openBtn = document.createElement('button');
        openBtn.className = 'btn-primary';
        openBtn.textContent = 'Open Website';
        openBtn.style.width = '100%';
        openBtn.style.marginTop = '12px';
        openBtn.addEventListener('click', () => {
            if (isValidUrl(item.link)) {
                showToast(t('opening_website'), 'success');
                window.open(item.link, '_blank', 'noopener,noreferrer');
            } else {
                showToast(t('cannot_open_url'), 'error');
            }
        });
        content.appendChild(openBtn);
    }
    
    await showScreen('detail');
}

function addDetailRow(container, label, value, copyCallback, isPassword, actualPassword) {
    const row = document.createElement('div');
    row.className = 'detail-row';
    
    const labelSpan = document.createElement('span');
    labelSpan.className = 'detail-label';
    labelSpan.textContent = label;
    
    const valueSpan = document.createElement('span');
    valueSpan.className = 'detail-value' + (isPassword ? ' password-value' : '');
    
    if (isPassword) {
        valueSpan.textContent = '••••••••••';
        
        // Toggle button
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'detail-action';
        toggleBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
        toggleBtn.style.cssText = 'background:none;border:none;cursor:pointer;padding:4px;color:var(--text-secondary);';
        
        let isRevealed = false;
        toggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            isRevealed = !isRevealed;
            valueSpan.textContent = isRevealed ? actualPassword : '••••••••••';
            valueSpan.style.letterSpacing = isRevealed ? '0' : '3px';
        });
        
        row.appendChild(labelSpan);
        row.appendChild(valueSpan);
        
        const actionsDiv = document.createElement('div');
        actionsDiv.className = 'detail-actions';
        actionsDiv.appendChild(toggleBtn);
        
        if (copyCallback) {
            const copyBtn = document.createElement('button');
            copyBtn.className = 'detail-action';
            copyBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`;
            copyBtn.style.cssText = 'background:none;border:none;cursor:pointer;padding:4px;color:var(--text-secondary);';
            copyBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                copyCallback();
            });
            actionsDiv.appendChild(copyBtn);
        }
        
        row.appendChild(actionsDiv);
    } else {
        valueSpan.textContent = value;
        row.appendChild(labelSpan);
        row.appendChild(valueSpan);
        
        if (copyCallback) {
            const copyBtn = document.createElement('button');
            copyBtn.className = 'detail-action';
            copyBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="16" height="16"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`;
            copyBtn.style.cssText = 'background:none;border:none;cursor:pointer;padding:4px;color:var(--text-secondary);';
            copyBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                copyCallback();
            });
            
            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'detail-actions';
            actionsDiv.appendChild(copyBtn);
            row.appendChild(actionsDiv);
        }
    }
    
    container.appendChild(row);
}

async function confirmDeleteItem(item) {
    const confirmed = await showConfirmModal(t('confirm_delete'));
    
    if (confirmed) {
        await dbDelete('vault', item.id);
        showToast('Deleted', 'success');
        await showScreen('home');
    }
}

/* ============================================
   FORM HANDLING
   ============================================ */

function openAddForm(type) {
    state.editingItem = null;
    dom.formTitle.textContent = t('add_new') + ' - ' + t(type);
    renderForm(type, null);
    showScreen('form');
}

function openEditForm(item) {
    state.editingItem = item;
    dom.formTitle.textContent = t('edit') + ' - ' + t(item.type);
    renderForm(item.type, item);
    showScreen('form');
}

function renderForm(type, item) {
    const form = dom.itemForm;
    form.innerHTML = '';
    form.dataset.type = type;
    
    // Name field
    const nameGroup = document.createElement('div');
    nameGroup.className = 'form-group';
    nameGroup.innerHTML = `
        <label class="form-label" for="field-name">${t('name')} *</label>
        <input type="text" id="field-name" class="form-input" value="${item?.name || ''}" required>
    `;
    form.appendChild(nameGroup);
    
    if (type === 'password') {
        // Username field
        const usernameGroup = document.createElement('div');
        usernameGroup.className = 'form-group';
        usernameGroup.innerHTML = `
            <label class="form-label" for="field-username">${t('username')}</label>
            <input type="text" id="field-username" class="form-input" value="${item?.username || ''}" autocomplete="off">
        `;
        form.appendChild(usernameGroup);
        
        // Password field
        const passwordGroup = document.createElement('div');
        passwordGroup.className = 'form-group';
        passwordGroup.innerHTML = `
            <label class="form-label" for="field-password">${t('password')} *</label>
            <div class="password-field-wrapper">
                <input type="password" id="field-password" class="form-input" value="${item?.password || ''}" required autocomplete="off">
                <button type="button" class="password-toggle-btn" id="btn-toggle-password" aria-label="Toggle password visibility">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                </button>
            </div>
        `;
        form.appendChild(passwordGroup);
        
        // Link field
        const linkGroup = document.createElement('div');
        linkGroup.className = 'form-group';
        linkGroup.innerHTML = `
            <label class="form-label" for="field-link">${t('link')}</label>
            <input type="url" id="field-link" class="form-input" value="${item?.link || ''}">
        `;
        form.appendChild(linkGroup);
    } else if (type === 'note') {
        // Content field
        const contentGroup = document.createElement('div');
        contentGroup.className = 'form-group';
        contentGroup.innerHTML = `
            <label class="form-label" for="field-content">Content *</label>
            <textarea id="field-content" class="form-textarea" required>${item?.content || ''}</textarea>
        `;
        form.appendChild(contentGroup);
    } else if (type === 'website') {
        // URL field
        const urlGroup = document.createElement('div');
        urlGroup.className = 'form-group';
        urlGroup.innerHTML = `
            <label class="form-label" for="field-url">URL *</label>
            <input type="url" id="field-url" class="form-input" value="${item?.link || ''}" required>
        `;
        form.appendChild(urlGroup);
    }
    
    // Category select
    const categoryGroup = document.createElement('div');
    categoryGroup.className = 'form-group';
    let categoryOptions = '';
    for (const cat of state.categories) {
        const selected = item?.category === cat.id ? 'selected' : '';
        categoryOptions += `<option value="${cat.id}" ${selected}>${cat.name}</option>`;
    }
    categoryGroup.innerHTML = `
        <label class="form-label" for="field-category">${t('category')}</label>
        <select id="field-category" class="form-select">
            ${categoryOptions}
        </select>
    `;
    form.appendChild(categoryGroup);
    
    // Notes field (for password and website types)
    if (type !== 'note') {
        const notesGroup = document.createElement('div');
        notesGroup.className = 'form-group';
        notesGroup.innerHTML = `
            <label class="form-label" for="field-notes">${t('notes')}</label>
            <textarea id="field-notes" class="form-textarea">${item?.notes || ''}</textarea>
        `;
        form.appendChild(notesGroup);
    }
    
    // Image upload
    const imageGroup = document.createElement('div');
    imageGroup.className = 'form-group';
    imageGroup.innerHTML = `
        <label class="form-label">Image (optional)</label>
        <div class="image-upload-area" id="image-upload-area">
            <span>Tap to upload image</span>
            ${item?.imageData ? `<img src="${item.imageData}" class="image-preview" alt="Preview">` : ''}
        </div>
    `;
    form.appendChild(imageGroup);
    
    // Favorite toggle
    const favoriteGroup = document.createElement('div');
    favoriteGroup.className = 'form-group';
    favoriteGroup.innerHTML = `
        <label class="form-label">
            <input type="checkbox" id="field-favorite" ${item?.favorite ? 'checked' : ''}>
            ${t('favorites')}
        </label>
    `;
    form.appendChild(favoriteGroup);
    
    // Submit buttons
    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'form-actions';
    actionsDiv.innerHTML = `
        <button type="submit" class="btn-primary">${t('save')}</button>
        <button type="button" class="btn-secondary" id="btn-cancel-form">${t('cancel')}</button>
    `;
    form.appendChild(actionsDiv);
    
    // Event listeners
    form.addEventListener('submit', handleFormSubmit);
    
    document.getElementById('btn-cancel-form').addEventListener('click', () => {
        showScreen('home');
    });
    
    const togglePasswordBtn = document.getElementById('btn-toggle-password');
    if (togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', () => {
            const passwordInput = document.getElementById('field-password');
            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                togglePasswordBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;
            } else {
                passwordInput.type = 'password';
                togglePasswordBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
            }
        });
    }
    
    const imageUploadArea = document.getElementById('image-upload-area');
    if (imageUploadArea) {
        imageUploadArea.addEventListener('click', () => {
            dom.imageFileInput.click();
        });
    }
}

async function handleFormSubmit(event) {
    event.preventDefault();
    
    const form = event.target;
    const type = form.dataset.type;
    
    // Validate
    const nameInput = document.getElementById('field-name');
    if (!nameInput.value.trim()) {
        showToast(t('required_field'), 'error');
        nameInput.focus();
        return;
    }
    
    let itemData = {
        id: state.editingItem?.id || generateId(),
        type: type,
        name: nameInput.value.trim(),
        category: document.getElementById('field-category')?.value || 'other',
        favorite: document.getElementById('field-favorite')?.checked || false,
        createdAt: state.editingItem?.createdAt || Date.now(),
        updatedAt: Date.now()
    };
    
    if (type === 'password') {
        itemData.username = document.getElementById('field-username')?.value || '';
        itemData.password = document.getElementById('field-password')?.value || '';
        itemData.link = document.getElementById('field-link')?.value || '';
        itemData.notes = document.getElementById('field-notes')?.value || '';
        
        if (!itemData.password) {
            showToast(t('required_field'), 'error');
            document.getElementById('field-password').focus();
            return;
        }
    } else if (type === 'note') {
        itemData.content = document.getElementById('field-content')?.value || '';
        
        if (!itemData.content.trim()) {
            showToast(t('required_field'), 'error');
            document.getElementById('field-content').focus();
            return;
        }
    } else if (type === 'website') {
        itemData.link = document.getElementById('field-url')?.value || '';
        itemData.notes = document.getElementById('field-notes')?.value || '';
        
        if (!itemData.link) {
            showToast(t('required_field'), 'error');
            document.getElementById('field-url').focus();
            return;
        }
        
        if (!isValidUrl(itemData.link)) {
            showToast(t('url_invalid'), 'error');
            document.getElementById('field-url').focus();
            return;
        }
    }
    
    // Handle image
    const imagePreview = document.querySelector('.image-preview');
    if (imagePreview) {
        itemData.imageData = imagePreview.src;
    } else if (state.editingItem?.imageData) {
        itemData.imageData = state.editingItem.imageData;
    }
    
    // Encrypt and save
    try {
        const encryptedItem = await encryptVaultItem(itemData, state.cryptoKey);
        await dbPut('vault', encryptedItem);
        
        showToast(t('save') + ' ✓', 'success');
        await showScreen('home');
    } catch (error) {
        console.error('Save error:', error);
        showToast(t('backup_failed'), 'error');
    }
}

function generateId() {
    const bytes = generateRandomBytes(16);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/* ============================================
   IMAGE HANDLING
   ============================================ */

async function handleImageUpload(file) {
    // Validate file type
    if (!ALLOWED_IMAGE_TYPES.includes(file.type)) {
        showToast(t('image_invalid_type'), 'error');
        return null;
    }
    
    // Validate file size
    if (file.size > MAX_IMAGE_SIZE) {
        showToast(t('image_too_large'), 'error');
        return null;
    }
    
    try {
        // Create image bitmap to check dimensions
        const bitmap = await createImageBitmap(file);
        const width = bitmap.width;
        const height = bitmap.height;
        
        // Resize if needed
        let targetWidth = width;
        let targetHeight = height;
        
        if (width > MAX_IMAGE_DIMENSION || height > MAX_IMAGE_DIMENSION) {
            const scale = Math.min(MAX_IMAGE_DIMENSION / width, MAX_IMAGE_DIMENSION / height);
            targetWidth = Math.round(width * scale);
            targetHeight = Math.round(height * scale);
        }
        
        // Create canvas for resizing
        const canvas = document.createElement('canvas');
        canvas.width = targetWidth;
        canvas.height = targetHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(bitmap, 0, 0, targetWidth, targetHeight);
        
        // Convert to compressed data URL
        const dataUrl = canvas.toDataURL('image/webp', 0.7);
        
        return dataUrl;
    } catch (error) {
        // Fallback to reading as data URL
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result);
            reader.onerror = reject;
            reader.readAsDataURL(file);
        });
    }
}

/* ============================================
   CLIPBOARD
   ============================================ */

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        
        // Clear clipboard after timeout
        const timeout = state.settings.clipboardTimeout;
        if (timeout && timeout !== 'off') {
            if (state.clipboardTimer) {
                clearTimeout(state.clipboardTimer);
            }
            
            state.clipboardTimer = setTimeout(async () => {
                try {
                    await navigator.clipboard.writeText('');
                } catch (error) {
                    // Clipboard clear not supported or failed
                }
            }, parseInt(timeout) * 1000);
        }
        
        return true;
    } catch (error) {
        return false;
    }
}

/* ============================================
   PASSWORD GENERATOR
   ============================================ */

function generatePassword(length, useUpper, useLower, useNumbers, useSymbols) {
    const upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lowerChars = 'abcdefghijklmnopqrstuvwxyz';
    const numberChars = '0123456789';
    const symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let charPool = '';
    if (useUpper) charPool += upperChars;
    if (useLower) charPool += lowerChars;
    if (useNumbers) charPool += numberChars;
    if (useSymbols) charPool += symbolChars;
    
    if (!charPool) return '';
    
    const bytes = generateRandomBytes(length);
    let password = '';
    
    for (let i = 0; i < length; i++) {
        const index = bytes[i] % charPool.length;
        password += charPool[index];
    }
    
    return password;
}

function updateGeneratedPassword() {
    const length = parseInt(dom.genLength.value);
    const useUpper = dom.genUppercase.checked;
    const useLower = dom.genLowercase.checked;
    const useNumbers = dom.genNumbers.checked;
    const useSymbols = dom.genSymbols.checked;
    
    state.generatedPassword = generatePassword(length, useUpper, useLower, useNumbers, useSymbols);
    dom.generatedPassword.textContent = state.generatedPassword || 'Select at least one option';
}

/* ============================================
   BACKUP & RESTORE
   ============================================ */

async function createBackup() {
    try {
        const items = await dbGetAll('vault');
        const categories = await dbGetAll('categories');
        const metadata = await dbGetAll('metadata');
        
        // Create backup structure - items remain encrypted
        const backup = {
            version: APP_VERSION,
            createdAt: Date.now(),
            items: items.map(item => ({
                id: item.id,
                type: item.type,
                encrypted: item.encrypted,
                category: item.category,
                favorite: item.favorite,
                createdAt: item.createdAt,
                updatedAt: item.updatedAt
            })),
            categories: categories,
            metadata: metadata.filter(m => m.key === 'pin_config')
        };
        
        const backupJson = JSON.stringify(backup);
        const blob = new Blob([backupJson], { type: 'application/json' });
        
        // Create download link
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'KEYBOX-backup.kbx';
        a.click();
        URL.revokeObjectURL(url);
        
        showToast(t('backup_created'), 'success');
    } catch (error) {
        console.error('Backup error:', error);
        showToast(t('backup_failed'), 'error');
    }
}

async function restoreBackup(file) {
    try {
        // Validate file
        if (!file || !file.name.endsWith('.kbx')) {
            showToast(t('invalid_backup'), 'error');
            return;
        }
        
        // Check file size (limit to 10MB)
        if (file.size > 10 * 1024 * 1024) {
            showToast(t('invalid_backup'), 'error');
            return;
        }
        
        const text = await file.text();
        const backup = JSON.parse(text);
        
        // Validate structure
        if (!backup.version || !backup.items || !Array.isArray(backup.items)) {
            showToast(t('invalid_backup'), 'error');
            return;
        }
        
        // Validate version compatibility
        if (backup.version !== APP_VERSION) {
            showToast(t('invalid_backup'), 'error');
            return;
        }
        
        // Validate each item structure
        for (const item of backup.items) {
            if (!item.id || !item.type || !item.encrypted || !item.encrypted.iv || !item.encrypted.data) {
                showToast(t('invalid_backup'), 'error');
                return;
            }
        }
        
        // Confirm restore
        const confirmed = await showConfirmModal('Restore this backup? This will replace all current data.');
        
        if (!confirmed) return;
        
        // Clear existing data
        await dbClear('vault');
        await dbClear('categories');
        
        // Restore items
        for (const item of backup.items) {
            await dbPut('vault', item);
        }
        
        // Restore categories
        if (backup.categories && Array.isArray(backup.categories)) {
            for (const cat of backup.categories) {
                await dbPut('categories', cat);
            }
        }
        
        // Restore PIN config if present
        if (backup.metadata && Array.isArray(backup.metadata)) {
            for (const meta of backup.metadata) {
                if (meta.key === 'pin_config') {
                    await dbPut('metadata', meta);
                    state.settings.pinEnabled = meta.enabled;
                }
            }
        }
        
        await loadCategories();
        await loadHomeData();
        updatePinStatusUI();
        
        showToast(t('backup_restored'), 'success');
    } catch (error) {
        console.error('Restore error:', error);
        showToast(t('invalid_backup'), 'error');
    }
}

/* ============================================
   DELETE ALL DATA
   ============================================ */

async function deleteAllData() {
    const confirmed1 = await showConfirmModal(t('confirm_delete_all'));
    
    if (!confirmed1) return;
    
    const confirmed2 = await showConfirmModal(t('confirm_delete_all_final'));
    
    if (!confirmed2) return;
    
    try {
        await dbClear('vault');
        await dbClear('categories');
        await dbClear('metadata');
        await dbClear('settings');
        
        // Reinitialize default categories
        await loadCategories();
        
        state.cryptoKey = null;
        state.isUnlocked = false;
        state.settings.pinEnabled = false;
        
        // Regenerate encryption key
        state.cryptoKey = await generateEncryptionKey();
        const exportedKey = await crypto.subtle.exportKey('raw', state.cryptoKey);
        await dbPut('metadata', {
            key: 'encryption_key',
            keyData: bufferToBase64(exportedKey)
        });
        
        state.isUnlocked = true;
        await showScreen('home');
        await loadHomeData();
        updatePinStatusUI();
        
        showToast('All data deleted', 'success');
    } catch (error) {
        console.error('Delete all error:', error);
        showToast(t('backup_failed'), 'error');
    }
}

/* ============================================
   SETTINGS UI
   ============================================ */

function loadSettingsUI() {
    dom.autoLockSelect.value = state.settings.autoLock;
    dom.clipboardTimeoutSelect.value = String(state.settings.clipboardTimeout);
    dom.themeSelect.value = state.settings.theme;
    dom.languageSelect.value = state.settings.language;
    updatePinStatusUI();
}

function updatePinStatusUI() {
    if (dom.pinStatusText) {
        dom.pinStatusText.textContent = state.settings.pinEnabled ? t('enabled') : t('disabled');
    }
}

async function togglePinProtection() {
    if (state.settings.pinEnabled) {
        // Remove PIN
        const confirmed = await showConfirmModal('Remove PIN protection?');
        if (confirmed) {
            await removePin();
            showToast(t('pin_removed'), 'success');
        }
    } else {
        // Create PIN
        showPinCreationModal();
    }
}

function showPinCreationModal() {
    const modalContent = dom.modalContent;
    modalContent.innerHTML = `
        <h3 class="modal-title">${t('create_pin')}</h3>
        <form id="pin-creation-form">
            <div class="form-group">
                <label class="form-label" for="new-pin">PIN (4 digits)</label>
                <input type="password" id="new-pin" class="form-input" inputmode="numeric" pattern="[0-9]*" maxlength="4" required>
            </div>
            <div class="form-group">
                <label class="form-label" for="confirm-pin">${t('confirm_pin')}</label>
                <input type="password" id="confirm-pin" class="form-input" inputmode="numeric" pattern="[0-9]*" maxlength="4" required>
            </div>
            <div class="modal-actions">
                <button type="submit" class="btn-primary">${t('save')}</button>
                <button type="button" class="btn-secondary" id="btn-cancel-pin">${t('cancel')}</button>
            </div>
        </form>
    `;
    
    dom.modalContainer.classList.remove('hidden');
    
    document.getElementById('pin-creation-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const newPin = document.getElementById('new-pin').value;
        const confirmPin = document.getElementById('confirm-pin').value;
        
        if (newPin.length !== 4 || !/^\d{4}$/.test(newPin)) {
            showToast('PIN must be 4 digits', 'error');
            return;
        }
        
        if (newPin !== confirmPin) {
            showToast(t('pin_mismatch'), 'error');
            return;
        }
        
        await setupPin(newPin);
        dom.modalContainer.classList.add('hidden');
        showToast(t('pin_created'), 'success');
    });
    
    document.getElementById('btn-cancel-pin').addEventListener('click', () => {
        dom.modalContainer.classList.add('hidden');
    });
}

/* ============================================
   AUTO LOCK
   ============================================ */

function resetAutoLockTimer() {
    if (state.autoLockTimer) {
        clearTimeout(state.autoLockTimer);
        state.autoLockTimer = null;
    }
    
    const autoLock = state.settings.autoLock;
    if (autoLock && autoLock !== 'off' && state.settings.pinEnabled) {
        state.autoLockTimer = setTimeout(async () => {
            await showLockScreen();
        }, parseInt(autoLock) * 1000);
    }
}

/* ============================================
   SEARCH
   ============================================ */

function handleSearch(query) {
    state.searchQuery = query.trim();
    
    if (query) {
        dom.btnClearSearch.classList.remove('hidden');
    } else {
        dom.btnClearSearch.classList.add('hidden');
    }
    
    loadItems();
}

/* ============================================
   THEME
   ============================================ */

function applyTheme(theme) {
    if (theme === 'system') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        document.documentElement.setAttribute('data-theme', prefersDark ? 'dark' : 'light');
    } else {
        document.documentElement.setAttribute('data-theme', theme);
    }
}

/* ============================================
   LANGUAGE
   ============================================ */

function applyLanguage(lang) {
    currentLang = lang;
    document.documentElement.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
    document.documentElement.setAttribute('lang', lang);
    
    // Update all i18n elements
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (translations[lang]?.[key]) {
            el.textContent = translations[lang][key];
        }
    });
}

/* ============================================
   TOAST & MODAL
   ============================================ */

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = 'toast' + (type !== 'info' ? ` ${type}` : '');
    toast.textContent = message;
    
    dom.toastContainer.appendChild(toast);
    
    setTimeout(() => {
        toast.classList.add('fade-out');
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, 2500);
}

function showConfirmModal(message) {
    return new Promise((resolve) => {
        const modalContent = dom.modalContent;
        modalContent.innerHTML = `
            <h3 class="modal-title">${t('confirm_delete')}</h3>
            <p class="modal-body">${message}</p>
            <div class="modal-actions">
                <button class="btn-danger" id="btn-confirm-yes">${t('delete')}</button>
                <button class="btn-secondary" id="btn-confirm-no">${t('cancel')}</button>
            </div>
        `;
        
        dom.modalContainer.classList.remove('hidden');
        
        document.getElementById('btn-confirm-yes').addEventListener('click', () => {
            dom.modalContainer.classList.add('hidden');
            resolve(true);
        });
        
        document.getElementById('btn-confirm-no').addEventListener('click', () => {
            dom.modalContainer.classList.add('hidden');
            resolve(false);
        });
        
        // Close on overlay click
        document.querySelector('.modal-overlay').addEventListener('click', () => {
            dom.modalContainer.classList.add('hidden');
            resolve(false);
        });
    });
}

/* ============================================
   VALIDATION
   ============================================ */

function isValidUrl(url) {
    try {
        const parsed = new URL(url);
        return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (error) {
        return false;
    }
}

function sanitizeText(text) {
    return String(text).replace(/[<>]/g, '');
}

/* ============================================
   SERVICE WORKER REGISTRATION
   ============================================ */

async function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
        try {
            await navigator.serviceWorker.register('service-worker.js');
        } catch (error) {
            console.warn('Service worker registration failed:', error);
        }
    }
}

/* ============================================
   EVENT LISTENERS
   ============================================ */

function setupEventListeners() {
    // Navigation
    dom.navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const nav = btn.dataset.nav;
            
            if (nav === 'search') {
                dom.searchInput.focus();
                showScreen('home');
            } else {
                showScreen(nav);
            }
        });
    });
    
    // Lock button
    dom.btnLock.addEventListener('click', async () => {
        if (state.settings.pinEnabled) {
            await showLockScreen();
        }
    });
    
    // Search
    dom.searchInput.addEventListener('input', (e) => {
        handleSearch(e.target.value);
    });
    
    dom.btnClearSearch.addEventListener('click', () => {
        dom.searchInput.value = '';
        handleSearch('');
    });
    
    // Section tabs
    dom.sectionTabs.addEventListener('click', (e) => {
        const tab = e.target.closest('.tab-btn');
        if (!tab) return;
        
        dom.sectionTabs.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        
        state.currentSection = tab.dataset.section;
        loadItems();
    });
    
    // Add buttons
    dom.btnAddPassword.addEventListener('click', () => openAddForm('password'));
    dom.btnAddNote.addEventListener('click', () => openAddForm('note'));
    dom.btnAddWebsite.addEventListener('click', () => openAddForm('website'));
    
    // Back buttons
    document.querySelectorAll('.back-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            showScreen('home');
        });
    });
    
    // PIN keypad
    dom.pinKeypad.addEventListener('click', (e) => {
        const key = e.target.closest('.pin-key, .pin-key-backspace');
        if (!key || key.disabled) return;
        
        const value = key.dataset.value;
        
        if (value === 'backspace') {
            if (dom.pinInput.value.length > 0) {
                dom.pinInput.value = dom.pinInput.value.slice(0, -1);
                updatePinDots();
            }
        } else {
            if (dom.pinInput.value.length < 4) {
                dom.pinInput.value += value;
                updatePinDots();
                
                if (dom.pinInput.value.length === 4) {
                    setTimeout(() => {
                        handlePinSubmit(dom.pinInput.value);
                    }, 200);
                }
            }
        }
    });
    
    // Hidden PIN input
    dom.pinInput.addEventListener('input', () => {
        dom.pinInput.value = dom.pinInput.value.replace(/[^0-9]/g, '').slice(0, 4);
        updatePinDots();
        
        if (dom.pinInput.value.length === 4) {
            setTimeout(() => {
                handlePinSubmit(dom.pinInput.value);
            }, 200);
        }
    });
    
    // Forgot PIN
    dom.btnForgotPin.addEventListener('click', async () => {
        const confirmed = await showConfirmModal(t('forgot_pin_message') + '\n\n' + t('delete_all_and_reset') + '?');
        
        if (confirmed) {
            await deleteAllData();
            dom.modalContainer.classList.add('hidden');
        }
    });
    
    // Settings
    dom.btnTogglePin.addEventListener('click', togglePinProtection);
    
    dom.autoLockSelect.addEventListener('change', async (e) => {
        state.settings.autoLock = e.target.value;
        await dbPut('settings', { key: 'autoLock', value: e.target.value });
        resetAutoLockTimer();
    });
    
    dom.clipboardTimeoutSelect.addEventListener('change', async (e) => {
        state.settings.clipboardTimeout = e.target.value === 'off' ? 'off' : parseInt(e.target.value);
        await dbPut('settings', { key: 'clipboardTimeout', value: e.target.value });
    });
    
    dom.themeSelect.addEventListener('change', async (e) => {
        state.settings.theme = e.target.value;
        await dbPut('settings', { key: 'theme', value: e.target.value });
        applyTheme(e.target.value);
    });
    
    dom.languageSelect.addEventListener('change', async (e) => {
        state.settings.language = e.target.value;
        await dbPut('settings', { key: 'language', value: e.target.value });
        applyLanguage(e.target.value);
    });
    
    dom.btnBackup.addEventListener('click', createBackup);
    
    dom.btnRestore.addEventListener('click', () => {
        dom.restoreFileInput.click();
    });
    
    dom.restoreFileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            restoreBackup(file);
        }
        e.target.value = '';
    });
    
    dom.btnDeleteAll.addEventListener('click', deleteAllData);
    
    // Image upload
    dom.imageFileInput.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) {
            const dataUrl = await handleImageUpload(file);
            
            if (dataUrl) {
                const uploadArea = document.getElementById('image-upload-area');
                if (uploadArea) {
                    uploadArea.innerHTML = `<img src="${dataUrl}" class="image-preview" alt="Preview">`;
                }
            }
        }
        e.target.value = '';
    });
    
    // Generator
    dom.genLength.addEventListener('input', () => {
        dom.genLengthValue.textContent = dom.genLength.value;
    });
    
    dom.btnGenerate.addEventListener('click', updateGeneratedPassword);
    
    dom.btnCopyGenerated.addEventListener('click', async () => {
        if (state.generatedPassword) {
            const success = await copyToClipboard(state.generatedPassword);
            if (success) {
                showToast(t('copied'), 'success');
            } else {
                showToast(t('copy_failed'), 'error');
            }
        }
    });
    
    dom.btnUsePassword.addEventListener('click', () => {
        if (state.generatedPassword) {
            // Navigate to add password form with generated password
            openAddForm('password');
            
            setTimeout(() => {
                const passwordInput = document.getElementById('field-password');
                if (passwordInput) {
                    passwordInput.value = state.generatedPassword;
                }
            }, 100);
        }
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Escape to close modal
        if (e.key === 'Escape') {
            dom.modalContainer.classList.add('hidden');
        }
        
        // Ctrl+K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            dom.searchInput.focus();
        }
    });
    
    // Visibility change - auto lock
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            // Clear sensitive data from UI
            clearSensitiveUI();
        } else if (document.visibilityState === 'visible') {
            // Check if auto lock should trigger
            if (state.settings.pinEnabled && state.autoLockTimer === null && state.isUnlocked) {
                // Already locked or timer expired
            }
        }
    });
    
    // Window blur - auto lock for short timeouts
    window.addEventListener('blur', () => {
        if (state.settings.autoLock === '30' && state.settings.pinEnabled && state.isUnlocked) {
            setTimeout(async () => {
                await showLockScreen();
            }, 30000);
        }
    });
}

function clearSensitiveUI() {
    // Clear any visible passwords
    const passwordFields = document.querySelectorAll('.detail-value.password-value');
    passwordFields.forEach(field => {
        field.textContent = '••••••••••';
    });
    
    // Clear generated password display
    if (dom.generatedPassword) {
        dom.generatedPassword.textContent = 'Click Generate';
    }
}

/* ============================================
   SETTINGS LOADING
   ============================================ */

async function loadSettings() {
    const settings = await dbGetAll('settings');
    
    for (const setting of settings) {
        if (setting.key === 'autoLock') {
            state.settings.autoLock = setting.value;
        } else if (setting.key === 'theme') {
            state.settings.theme = setting.value;
        } else if (setting.key === 'language') {
            state.settings.language = setting.value;
        } else if (setting.key === 'clipboardTimeout') {
            state.settings.clipboardTimeout = setting.value === 'off' ? 'off' : parseInt(setting.value);
        }
    }
    
    // Apply settings
    applyTheme(state.settings.theme);
    applyLanguage(state.settings.language);
}

/* ============================================
   INITIALIZATION
   ============================================ */

async function initApp() {
    try {
        // Cache DOM elements
        cacheDomElements();
        
        // Open database
        state.db = await openDatabase();
        
        // Load settings
        await loadSettings();
        
        // Setup event listeners
        setupEventListeners();
        
        // Initialize authentication
        await initAuth();
        
        // Register service worker
        await registerServiceWorker();
        
        // Handle system theme changes
        window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
            if (state.settings.theme === 'system') {
                applyTheme('system');
            }
        });
        
    } catch (error) {
        console.error('Initialization error:', error);
        showToast('Failed to initialize application', 'error');
    }
}

// Start the application
document.addEventListener('DOMContentLoaded', initApp);

// Handle unhandled errors
window.addEventListener('error', (event) => {
    console.error('Unhandled error:', event.error);
    // Don't show technical details to user
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled rejection:', event.reason);
    // Don't show technical details to user
});
