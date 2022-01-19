#ifndef CONSTANTS_H
#define CONSTANTS_H

struct Constants
{
    static inline const char* appName = "l8w8jwtGUI";
    static inline const char* appVersion = "1.0.0";
    static inline const char* orgName = "Glitched Polygons";
    static inline const char* orgDomain = "glitchedpolygons.com";

    struct Settings
    {
        static inline const char* saveClaimsOnQuit = "SaveClaimsOnQuit";
        static inline const char* saveWindowSizeOnQuit = "SaveWindowSizeOnQuit";
        static inline const char* selectTextOnFocus = "SelectTextFieldContentOnFocus";
        static inline const char* windowWidth = "WindowWidth";
        static inline const char* windowHeight = "WindowHeight";
        static inline const char* issuer = "Issuer";
        static inline const char* subject = "Subject";
        static inline const char* audience = "Audience";
        static inline const char* customClaims = "CustomClaims";
    };
};

#endif // CONSTANTS_H
