#ifndef CONSTANTS_H
#define CONSTANTS_H

struct Constants
{
    static inline const char* appName = "l8w8jwtGUI";
    static inline const char* appVersion = "1.0.3";
    static inline const char* orgName = "Glitched Polygons GmbH";
    static inline const char* orgDomain = "glitchedpolygons.com";
    static constexpr unsigned char iatToleranceSeconds = 8;
    static constexpr unsigned char expToleranceSeconds = 8;
    static constexpr unsigned char nbfToleranceSeconds = 8;
    static constexpr int minEntropyToCollect = 4096;

    struct Settings
    {
        static inline const char* saveClaimsOnQuit = "SaveClaimsOnQuit";
        static inline const char* saveWindowSizeOnQuit = "SaveWindowSizeOnQuit";
        static inline const char* selectTextOnFocus = "SelectTextFieldContentOnFocus";
        static inline const char* windowWidth = "WindowWidth";
        static inline const char* windowHeight = "WindowHeight";
        static inline const char* algorithm = "Algorithm";
        static inline const char* issuer = "Issuer";
        static inline const char* subject = "Subject";
        static inline const char* audience = "Audience";
        static inline const char* customClaims = "CustomClaims";
    };
};

#endif // CONSTANTS_H
