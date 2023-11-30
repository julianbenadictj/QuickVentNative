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
    flex: 0.2,
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: background.primary,
  },
};

export const qvHomeLayoutInternalContainer = {
  container: {
    backgroundColor: background.primary,
    flex: 1,
    justifyContent: "flex-end",
    alignItems: "center",
  },
};

export const qvHomeLayoutHeader = {
  text: {
    color: "white",
  },
};
