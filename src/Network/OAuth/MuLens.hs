{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RankNTypes            #-}

-- |
-- Module      : Network.OAuth.MuLens
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Tiny, @Control.Lens@ compatibility layer.

module Network.OAuth.MuLens (
  -- * Basics
  view, set,
  -- * Generalizations
  over, foldMapOf,
  -- * Building
  lens,
  -- * Convenience
  (<&>), (&), (^.), (.~)
  ) where

import           Control.Applicative
import           Control.Monad.Reader
import           Data.Functor.Constant
import           Data.Functor.Identity

type Lens s t a b = forall f . Functor f => (a -> f b) -> s -> f t

view :: MonadReader s m => ((a -> Constant a a) -> s -> Constant a s) -> m a
view inj = asks (foldMapOf inj id)
{-# INLINE view #-}

over :: ((a -> Identity b) -> s -> Identity t) -> (a -> b) -> s -> t
over inj f = runIdentity . inj (Identity . f)
{-# INLINE over #-}

set :: ((a -> Identity b) -> s -> Identity t) -> b -> s -> t
set l = over l . const
{-# INLINE set #-}

foldMapOf :: ((a -> Constant r b) -> s -> Constant r t) -> (a -> r) -> s -> r
foldMapOf inj f = getConstant . inj (Constant . f)
{-# INLINE foldMapOf #-}

lens :: (s -> a) -> (s -> b -> t) -> Lens s t a b
lens gt st inj x = st x <$> inj (gt x)
{-# INLINE lens #-}

infixl 5 <&>
(<&>) :: Functor f => f a -> (a -> b) -> f b
(<&>) = flip (<$>)
{-# INLINE (<&>) #-}

infixl 1 &
(&) :: b -> (b -> c) -> c
(&) = flip ($)
{-# INLINE (&) #-}

infixl 8 ^.
(^.) ::  s -> ((a -> Constant a a) -> s -> Constant a s) -> a
(^.) = flip view
{-# INLINE (^.) #-}

infixr 4 .~
(.~) :: ((a -> Identity b) -> s -> Identity t) -> (a -> b) -> s -> t
(.~) = over
{-# INLINE (.~) #-}
