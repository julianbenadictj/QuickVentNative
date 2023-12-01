import { Appearance, Platform } from "react-native";
import "../../themesource/atlas_core/native/api";
import {
  brand,
  darkMode,
  backgroundDefaults,
  background,
  contrast,
} from "./custom-variables";

// Custom Classes
export const qvScroll = {
  container: {
    backgroundColor: "#FFFFFF",
  },
};

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
  container: {
    /* height: 24,
    width: 120, */
  },
  text: {
    color: "white",
    fontSize: 24,
  },
};

export const qvHomeSearchOuterContainer = {
  container: {
    backgroundColor: background.primary,
    display: "flex",
    flexDirection: "row",
    justifyContent: "center",
    alignItems: "flex-top",
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

export const qvHomeFindEventTextContainer = {
  container: { flex: 1, paddingVertical: 7 },
};

export const qvHomeFindEventText = {
  text: { fontSize: 16, color: "#FFFFFF80" },
};

export const qvHomeDictationIconContainer = {
  container: { paddingHorizontal: 8, marginLeft: "auto", alignSelf: "center" },
};

export const qvHomeDictationIcon = { alignSelf: "center" };
