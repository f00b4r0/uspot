include $(TOPDIR)/rules.mk

PKG_NAME:=uspot
PKG_RELEASE:=1

PKG_LICENSE:=GPL-2.0
PKG_MAINTAINER:=John Crispin <john@phrozen.org>

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/uspot
  SECTION:=net
  CATEGORY:=Network
  TITLE:=hotspot daemon
  DEPENDS:=+spotfilter +uhttpd-mod-ucode +libradcli +conntrack \
	   +ucode-mod-math +ucode-mod-nl80211 +ucode-mod-rtnl +ucode-mod-uloop +ratelimit \
	   +libubus +libubox +libuci
endef

define Package/uspot/install
	$(INSTALL_DIR) $(1)/usr/bin/ $(1)/usr/lib/ucode
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/radius-client $(1)/usr/bin/radius-client
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uspot-das $(1)/usr/bin/uspot-das
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/libuam.so $(1)/usr/lib/ucode/uam.so
	$(CP) ./files/* $(1)
endef

$(eval $(call BuildPackage,uspot))
