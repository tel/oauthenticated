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
  (<&>), (&), (^.), (.~), (%~),
  ) where

import           Data.Functor.Identity
import           Data.Functor.Constant

view :: ((a -> Constant a a) -> s -> Constant a s) -> s -> a
view inj = foldMapOf inj id
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
(.~) :: ((a -> Identity b) -> s -> Identity t) -> b -> s -> t
(.~) = set
{-# INLINE (.~) #-}

infixr 4 %~
(%~) :: ((a -> Identity b) -> s -> Identity t) -> (a -> b) -> s -> t
(%~) = over
{-# INLINE (%~) #-}
