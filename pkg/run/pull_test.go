package run

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePullPolicy(t *testing.T) {
	type testCase struct {
		in      string
		want    PullPolicy
		wantErr bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		got, err := ParsePullPolicy(tc.in)
		if tc.wantErr {
			require.Error(t, err)
			return
		}
		require.NoError(t, err)
		assert.Equal(t, tc.want, got)
	}

	t.Run("defaults to missing", func(t *testing.T) {
		tester(t, testCase{want: PullMissing})
	})
	t.Run("accepts always", func(t *testing.T) {
		tester(t, testCase{in: "always", want: PullAlways})
	})
	t.Run("accepts never", func(t *testing.T) {
		tester(t, testCase{in: "never", want: PullNever})
	})
	t.Run("rejects an unknown policy", func(t *testing.T) {
		tester(t, testCase{in: "if_not_present", wantErr: true})
	})
}

func TestEnsureImage(t *testing.T) {
	type testCase struct {
		policy     PullPolicy
		missing    bool
		existsErr  error
		wantPulled bool
		wantErr    string
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		rt := &captureRuntime{missing: tc.missing, existsErr: tc.existsErr}
		err := ensureImage(context.Background(), rt, testImage, tc.policy, io.Discard)
		if tc.wantErr != "" {
			require.ErrorContains(t, err, tc.wantErr)
		} else {
			require.NoError(t, err)
		}
		assert.Equal(t, tc.wantPulled, len(rt.pulled) == 1, "pulled %v", rt.pulled)
	}

	t.Run("missing uses a local image", func(t *testing.T) {
		tester(t, testCase{policy: PullMissing})
	})
	t.Run("missing pulls an absent image", func(t *testing.T) {
		tester(t, testCase{policy: PullMissing, missing: true, wantPulled: true})
	})
	t.Run("empty policy acts as missing", func(t *testing.T) {
		tester(t, testCase{missing: true, wantPulled: true})
	})
	t.Run("always pulls a local image", func(t *testing.T) {
		tester(t, testCase{policy: PullAlways, wantPulled: true})
	})
	t.Run("never uses a local image", func(t *testing.T) {
		tester(t, testCase{policy: PullNever})
	})
	t.Run("never refuses an absent image", func(t *testing.T) {
		tester(t, testCase{policy: PullNever, missing: true, wantErr: testImage + " is not present locally and the pull policy is never"})
	})
	t.Run("reports a failed check", func(t *testing.T) {
		tester(t, testCase{policy: PullMissing, existsErr: errors.New("daemon down"), wantErr: "daemon down"})
	})
}

func TestPrepareImage(t *testing.T) {
	type testCase struct {
		build      *ImageBuild
		policy     PullPolicy
		missing    bool
		wantBuilt  bool
		wantParent bool
		wantPulled bool
	}
	tester := func(t *testing.T, tc testCase) {
		t.Helper()
		rt := &captureRuntime{missing: tc.missing}
		err := prepareImage(context.Background(), rt, testImage, tc.build, tc.policy, io.Discard)
		require.NoError(t, err)
		built := rt.build.Tags != nil
		assert.Equal(t, tc.wantBuilt, built, "built")
		if built {
			assert.Equal(t, tc.build.Context, rt.build.Context)
			assert.Equal(t, tc.build.Dockerfile, rt.build.Dockerfile)
		}
		assert.Equal(t, tc.wantParent, rt.build.PullParent, "PullParent")
		assert.Equal(t, tc.wantPulled, len(rt.pulled) == 1, "pulled %v", rt.pulled)
	}
	build := &ImageBuild{Context: "/ctx", Dockerfile: "Dockerfile", Tags: []string{testImage}}

	t.Run("builds a build", func(t *testing.T) {
		tester(t, testCase{build: build, missing: true, wantBuilt: true})
	})
	t.Run("refreshes the base under always", func(t *testing.T) {
		tester(t, testCase{build: build, policy: PullAlways, wantBuilt: true, wantParent: true})
	})
	t.Run("fetches an image without a build", func(t *testing.T) {
		tester(t, testCase{missing: true, wantPulled: true})
	})
}
