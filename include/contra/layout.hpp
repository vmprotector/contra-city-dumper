#pragma once

#include "contra/model.hpp"

namespace contra {

struct LayoutOptions {
    bool enabled = true;
    bool gcAware = true;
};

void computeLayouts(model::SdkModel& model, const LayoutOptions& options);

}  // namespace contra
