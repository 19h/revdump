// Test target for revdump vtable stub generation and devirtualization
// Compile: x86_64-w64-mingw32-g++ -o test_vtable.exe test_vtable.cpp -static
//
// This test creates GLOBAL POINTERS directly to heap objects with vtables,
// which is the pattern revdump is designed to handle.

#include <windows.h>
#include <cstdio>
#include <cstdlib>

// ============================================================================
// Interface hierarchies with virtual methods
// ============================================================================

class IService {
public:
    virtual ~IService() = default;
    virtual const char* getName() const = 0;
    virtual void initialize() = 0;
    virtual void shutdown() = 0;
    virtual int getStatus() const = 0;
};

class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log(const char* msg) = 0;
    virtual void setLevel(int level) = 0;
    virtual int getLevel() const = 0;
};

class INetworkClient {
public:
    virtual ~INetworkClient() = default;
    virtual bool connect(const char* host, int port) = 0;
    virtual void disconnect() = 0;
    virtual bool isConnected() const = 0;
    virtual int send(const void* data, int len) = 0;
    virtual int receive(void* buffer, int maxLen) = 0;
};

class IRenderer {
public:
    virtual ~IRenderer() = default;
    virtual void beginFrame() = 0;
    virtual void endFrame() = 0;
    virtual void drawRect(int x, int y, int w, int h) = 0;
    virtual void clear(int r, int g, int b) = 0;
    virtual int getFrameCount() const = 0;
};

class IAudioEngine {
public:
    virtual ~IAudioEngine() = default;
    virtual void playSound(int soundId) = 0;
    virtual void stopSound(int soundId) = 0;
    virtual void setVolume(float vol) = 0;
    virtual float getVolume() const = 0;
};

// ============================================================================
// Concrete implementations
// ============================================================================

class ConsoleLogger : public ILogger {
    int level_;
    char prefix_[32];
public:
    ConsoleLogger(const char* prefix) : level_(1) {
        strncpy(prefix_, prefix, sizeof(prefix_) - 1);
        prefix_[sizeof(prefix_) - 1] = '\0';
    }

    void log(const char* msg) override {
        printf("[%s] %s\n", prefix_, msg);
    }

    void setLevel(int level) override { level_ = level; }
    int getLevel() const override { return level_; }
};

class FileLogger : public ILogger {
    int level_;
    char filename_[256];
    int logCount_;
public:
    FileLogger(const char* filename) : level_(2), logCount_(0) {
        strncpy(filename_, filename, sizeof(filename_) - 1);
        filename_[sizeof(filename_) - 1] = '\0';
    }

    void log(const char* msg) override {
        logCount_++;
        printf("[FILE:%s #%d] %s\n", filename_, logCount_, msg);
    }

    void setLevel(int level) override { level_ = level; }
    int getLevel() const override { return level_; }
};

class NetworkService : public IService, public INetworkClient {
    char name_[64];
    char host_[256];
    int port_;
    bool connected_;
    int status_;
    int bytesSent_;
    int bytesReceived_;
public:
    NetworkService(const char* name)
        : port_(0), connected_(false), status_(0), bytesSent_(0), bytesReceived_(0) {
        strncpy(name_, name, sizeof(name_) - 1);
        name_[sizeof(name_) - 1] = '\0';
        host_[0] = '\0';
    }

    // IService
    const char* getName() const override { return name_; }
    void initialize() override {
        status_ = 1;
        printf("[NetworkService:%s] Initialized\n", name_);
    }
    void shutdown() override {
        disconnect();
        status_ = 0;
        printf("[NetworkService:%s] Shutdown\n", name_);
    }
    int getStatus() const override { return status_; }

    // INetworkClient
    bool connect(const char* host, int port) override {
        strncpy(host_, host, sizeof(host_) - 1);
        port_ = port;
        connected_ = true;
        printf("[NetworkService:%s] Connected to %s:%d\n", name_, host_, port_);
        return true;
    }
    void disconnect() override {
        connected_ = false;
        printf("[NetworkService:%s] Disconnected\n", name_);
    }
    bool isConnected() const override { return connected_; }
    int send(const void* data, int len) override {
        bytesSent_ += len;
        return len;
    }
    int receive(void* buffer, int maxLen) override {
        bytesReceived_ += maxLen;
        return maxLen;
    }
};

class GraphicsRenderer : public IService, public IRenderer {
    char name_[64];
    int status_;
    int frameCount_;
    int width_, height_;
public:
    GraphicsRenderer(const char* name, int w, int h)
        : status_(0), frameCount_(0), width_(w), height_(h) {
        strncpy(name_, name, sizeof(name_) - 1);
        name_[sizeof(name_) - 1] = '\0';
    }

    // IService
    const char* getName() const override { return name_; }
    void initialize() override {
        status_ = 1;
        printf("[Renderer:%s] Initialized %dx%d\n", name_, width_, height_);
    }
    void shutdown() override {
        status_ = 0;
        printf("[Renderer:%s] Shutdown after %d frames\n", name_, frameCount_);
    }
    int getStatus() const override { return status_; }

    // IRenderer
    void beginFrame() override { }
    void endFrame() override { frameCount_++; }
    void drawRect(int x, int y, int w, int h) override {
        // Simulate drawing
    }
    void clear(int r, int g, int b) override { }
    int getFrameCount() const override { return frameCount_; }
};

class AudioService : public IService, public IAudioEngine {
    char name_[64];
    int status_;
    float volume_;
    int soundsPlaying_;
public:
    AudioService(const char* name)
        : status_(0), volume_(1.0f), soundsPlaying_(0) {
        strncpy(name_, name, sizeof(name_) - 1);
        name_[sizeof(name_) - 1] = '\0';
    }

    // IService
    const char* getName() const override { return name_; }
    void initialize() override {
        status_ = 1;
        printf("[Audio:%s] Initialized\n", name_);
    }
    void shutdown() override {
        status_ = 0;
        printf("[Audio:%s] Shutdown\n", name_);
    }
    int getStatus() const override { return status_; }

    // IAudioEngine
    void playSound(int soundId) override { soundsPlaying_++; }
    void stopSound(int soundId) override { if (soundsPlaying_ > 0) soundsPlaying_--; }
    void setVolume(float vol) override { volume_ = vol; }
    float getVolume() const override { return volume_; }
};

// ============================================================================
// GLOBAL POINTERS TO HEAP OBJECTS WITH VTABLES
// These are the key patterns revdump should detect and handle
// ============================================================================

// Direct interface pointers (single vtable at offset 0)
ILogger* g_logger = nullptr;
ILogger* g_fileLogger = nullptr;

// Service pointers (multiple inheritance = multiple vtables)
IService* g_networkService = nullptr;
IService* g_graphicsService = nullptr;
IService* g_audioService = nullptr;

// Same objects via different interface (tests vtable offset handling)
INetworkClient* g_networkClient = nullptr;
IRenderer* g_renderer = nullptr;
IAudioEngine* g_audioEngine = nullptr;

// Array of services
IService* g_services[8] = {nullptr};
int g_serviceCount = 0;

// ============================================================================
// Functions that use virtual calls through globals
// These generate the mov rcx,[global]; mov rax,[rcx]; call [rax+N] patterns
// ============================================================================

void logMessage(const char* msg) {
    if (g_logger) {
        g_logger->log(msg);  // Virtual call through global
    }
}

void logToFile(const char* msg) {
    if (g_fileLogger) {
        g_fileLogger->log(msg);  // Virtual call through global
    }
}

void initializeAllServices() {
    printf("\n=== Initializing Services ===\n");
    for (int i = 0; i < g_serviceCount; i++) {
        if (g_services[i]) {
            g_services[i]->initialize();  // Virtual call through global array
        }
    }
}

void shutdownAllServices() {
    printf("\n=== Shutting Down Services ===\n");
    for (int i = g_serviceCount - 1; i >= 0; i--) {
        if (g_services[i]) {
            g_services[i]->shutdown();  // Virtual call through global array
        }
    }
}

void printServiceStatus() {
    printf("\n=== Service Status ===\n");
    for (int i = 0; i < g_serviceCount; i++) {
        if (g_services[i]) {
            printf("  [%d] %s: status=%d\n",
                   i,
                   g_services[i]->getName(),   // Virtual call
                   g_services[i]->getStatus()); // Virtual call
        }
    }
}

void networkTest() {
    if (g_networkClient) {
        g_networkClient->connect("127.0.0.1", 8080);  // Virtual call

        char data[] = "Hello, Server!";
        g_networkClient->send(data, sizeof(data));  // Virtual call

        char buffer[256];
        g_networkClient->receive(buffer, sizeof(buffer));  // Virtual call

        printf("  Network connected: %s\n",
               g_networkClient->isConnected() ? "yes" : "no");  // Virtual call
    }
}

void renderFrame() {
    if (g_renderer) {
        g_renderer->beginFrame();  // Virtual call
        g_renderer->clear(0, 0, 0);  // Virtual call
        g_renderer->drawRect(100, 100, 200, 150);  // Virtual call
        g_renderer->endFrame();  // Virtual call
    }
}

void playTestSounds() {
    if (g_audioEngine) {
        g_audioEngine->setVolume(0.8f);  // Virtual call
        g_audioEngine->playSound(1);  // Virtual call
        g_audioEngine->playSound(2);  // Virtual call
        printf("  Audio volume: %.2f\n", g_audioEngine->getVolume());  // Virtual call
    }
}

// ============================================================================
// Setup and main
// ============================================================================

void createGlobalObjects() {
    printf("=== Creating Global Objects ===\n");

    // Create loggers (single inheritance - vtable at offset 0)
    g_logger = new ConsoleLogger("MAIN");
    g_fileLogger = new FileLogger("debug.log");

    printf("  g_logger       @ %p (ConsoleLogger)\n", (void*)g_logger);
    printf("  g_fileLogger   @ %p (FileLogger)\n", (void*)g_fileLogger);

    // Create services (multiple inheritance - multiple vtables)
    NetworkService* netSvc = new NetworkService("NetSvc");
    GraphicsRenderer* gfxSvc = new GraphicsRenderer("GfxSvc", 1920, 1080);
    AudioService* audioSvc = new AudioService("AudioSvc");

    // Store as IService* (first vtable)
    g_networkService = netSvc;
    g_graphicsService = gfxSvc;
    g_audioService = audioSvc;

    // Store via secondary interfaces (different vtable offsets)
    g_networkClient = netSvc;  // Second vtable in NetworkService
    g_renderer = gfxSvc;       // Second vtable in GraphicsRenderer
    g_audioEngine = audioSvc;  // Second vtable in AudioService

    printf("  g_networkService  @ %p (as IService)\n", (void*)g_networkService);
    printf("  g_networkClient   @ %p (as INetworkClient)\n", (void*)g_networkClient);
    printf("  g_graphicsService @ %p (as IService)\n", (void*)g_graphicsService);
    printf("  g_renderer        @ %p (as IRenderer)\n", (void*)g_renderer);
    printf("  g_audioService    @ %p (as IService)\n", (void*)g_audioService);
    printf("  g_audioEngine     @ %p (as IAudioEngine)\n", (void*)g_audioEngine);

    // Fill service array
    g_services[g_serviceCount++] = g_networkService;
    g_services[g_serviceCount++] = g_graphicsService;
    g_services[g_serviceCount++] = g_audioService;

    printf("  g_services array has %d entries\n", g_serviceCount);
}

void runTests() {
    printf("\n=== Running Virtual Call Tests ===\n");

    logMessage("Test message via g_logger");
    logToFile("Test message via g_fileLogger");

    initializeAllServices();
    printServiceStatus();

    networkTest();

    for (int i = 0; i < 5; i++) {
        renderFrame();
    }
    printf("  Rendered %d frames\n", g_renderer ? g_renderer->getFrameCount() : 0);

    playTestSounds();
}

void cleanup() {
    printf("\n=== Cleanup ===\n");

    shutdownAllServices();

    // Note: some pointers alias the same object, so only delete once
    delete static_cast<NetworkService*>(g_networkService);
    delete static_cast<GraphicsRenderer*>(g_graphicsService);
    delete static_cast<AudioService*>(g_audioService);
    delete static_cast<ConsoleLogger*>(g_logger);
    delete static_cast<FileLogger*>(g_fileLogger);
}

int main() {
    printf("=============================================\n");
    printf("  RevDump VTable Test Program\n");
    printf("  PID: %lu\n", GetCurrentProcessId());
    printf("  Base: %p\n", (void*)GetModuleHandle(NULL));
    printf("=============================================\n\n");

    createGlobalObjects();
    runTests();

    printf("\n[*] Loading revdump.dll...\n");
    HMODULE hDll = LoadLibraryA("revdump.dll");

    if (hDll) {
        printf("[*] DLL loaded successfully\n");
    } else {
        printf("[!] Failed to load DLL (error %lu)\n", GetLastError());
        printf("[*] Continuing anyway - you can inject manually\n");
    }

    printf("\n[*] Waiting for dump... Press Ctrl+C to exit.\n");
    printf("[*] Global pointers for verification:\n");
    printf("    g_logger         = %p\n", (void*)g_logger);
    printf("    g_fileLogger     = %p\n", (void*)g_fileLogger);
    printf("    g_networkService = %p\n", (void*)g_networkService);
    printf("    g_networkClient  = %p\n", (void*)g_networkClient);
    printf("    g_graphicsService= %p\n", (void*)g_graphicsService);
    printf("    g_renderer       = %p\n", (void*)g_renderer);
    printf("    g_audioService   = %p\n", (void*)g_audioService);
    printf("    g_audioEngine    = %p\n", (void*)g_audioEngine);

    // Keep running
    int tick = 0;
    while (true) {
        Sleep(1000);
        tick++;

        if (tick % 10 == 0) {
            printf("[*] Tick %d - still running\n", tick);

            // Periodic virtual calls to keep patterns visible
            if (g_logger) g_logger->log("Heartbeat");
            if (g_renderer) {
                g_renderer->beginFrame();
                g_renderer->endFrame();
            }
        }
    }

    cleanup();
    return 0;
}
