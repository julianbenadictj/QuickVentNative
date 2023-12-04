import "../../themesource/atlas_core/native/api";
import {
  brand,
  darkMode,
  backgroundDefaults,
  background,
  contrast,
} from "./custom-variables";

// Custom Classes

// LAYOUT STYLING BELOW:

export const qvHomeLayoutContainer = {
  container: {
    paddingBottom: 9,
    paddingTop: 65, //(54 from the space above this container that contains time, wifi, etc) + (11 actual top padding)
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: background.primary,
  },
};

export const qvHomeLayoutInternalContainer = {
  container: {
    backgroundColor: background.primary,
    justifyContent: "flex-end",
    alignItems: "center",
  },
};

export const qvHomeLayoutHeader = {
  text: {
    color: "white",
    fontSize: 24,
  },
};

// SEARCH BAR STYLING BELOW:

export const qvHomeSearchOuterContainer = {
  container: {
    backgroundColor: background.primary,
    display: "flex",
    flexDirection: "row",
    justifyContent: "center",
    paddingHorizontal: 16,
    paddingBottom: 15,
  },
};

export const qvHomeSearchInnerContainer = {
  container: {
    backgroundColor: "#7676801F",
    width: `100%`,
    display: "flex",
    flexDirection: "row",
    alignContent: "center",
    marginHorizontal: 16,
    borderRadius: 10,
  },
};

export const qvHomeSearchIconContainer = {
  container: {
    paddingHorizontal: 8,
    alignSelf: "center",
  },
};

export const qvHomeSearchIcon = { alignSelf: "center" };

export const qvHomeSearchTextContainer = {
  container: { flex: 1, paddingVertical: 7 },
};

export const qvHomeSearchText = {
  text: { fontSize: 16, color: "#FFFFFF80" }, //white 50% transparency
};

export const qvHomeDictationIconContainer = {
  container: { paddingHorizontal: 8, marginLeft: "auto", alignSelf: "center" },
};

export const qvHomeDictationIcon = { alignSelf: "center" };

// EVENT CARD STYLING BELOW

export const qvEventCardOuterWrapper = {
  container: {
    width: `100%`,
    justifyContent: "center",
    top: 0,
    left: 0,
  },
};

export const qvEventCardInnerWrapper = {
  container: {
    borderRadius: 16,
    display: "flex",
    flexDirection: "column",
    width: 288,
    height: 216,
    marginTop: 8,
    alignSelf: "center",
  },
};

export const qvEventBadgeContainer = {
  container: {
    top: 0,
    right: 0,
    marginRight: 13,
    marginTop: 14,
    paddingHorizontal: 8,
    paddingVertical: 2,
    backgroundColor: brand.warningLight,
    borderStyle: "solid",
    borderWidth: 1,
    borderColor: brand.warning,
    borderRadius: 4,
    position: "absolute",
  },
};

export const qvEventBadgeText = {
  text: {
    color: brand.primary,
    fontSize: 14,
  },
};

export const qvEventImageContainer = { container: {} };

export const qvEventImage = {
  image: {
    height: 120,
    width: 288,
    borderTopLeftRadius: 16,
    borderTopRightRadius: 16,
    position: "absolute",
  },
};

export const qvEventTextContainer = {
  container: {
    height: 96,
    width: 288,
    padding: 16,
    paddingTop: 8,
    marginTop: 120,
    borderStyle: "solid",
    borderWidth: 1,
    borderColor: brand.border,
    borderBottomLeftRadius: 16,
    borderBottomRightRadius: 16,
    borderTopWidth: 0,

    //shadows
    backgroundColor: "white",
    elevation: 2,
    shadowColor: brand.primary,
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.16,
    shadowRadius: 4.65,
  },
};

export const qvEventTitleText = {
  text: { color: brand.primary, fontSize: 18 },
};

export const qvEventDateText = {
  text: { color: brand.primary, fontSize: 14 },
};

//HOMEPAGE CONTENT STYLING BELOW:
export const qvScroll = {
  container: {
    backgroundColor: "white",
  },
};
